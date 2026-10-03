#!/usr/bin/env python3
"""
Ollama DuckDB Web Dashboard

A responsive, high-performance web dashboard for exploring, filtering, searching,
and querying Ollama target scan records and discovered models persisted in DuckDB.

Features:
  - Real-time search across hosts, IPs, versions, models, and error messages
  - Multi-dimensional filtering (authorization status, models, ports, speeds)
  - Interactive Models Registry with host popularity and architecture tags
  - In-browser DuckDB SQL Studio with presets and CSV/JSON export
  - Live Target Prober for on-demand host scanning and instant database upsert
  - Deep inspection modal with API breakdowns and raw JSON viewer
  - Built-in zero-dependency HTTP server with multi-threaded request handling
"""

import argparse
import csv
import datetime
import io
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

try:
    import duckdb
    HAS_DUCKDB = True
except ImportError:
    duckdb = None  # type: ignore
    HAS_DUCKDB = False

# Import probe and helper functions from ollama_cli if available
try:
    from ollama_cli import (
        format_bytes,
        format_target_status_brief,
        init_duckdb,
        parse_target,
        probe_target,
        save_target_to_duckdb,
    )
except ImportError:
    def format_bytes(num_bytes: Optional[int]) -> str:
        if num_bytes is None:
            return "N/A"
        n = float(num_bytes)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(n) < 1024.0:
                val = f"{n:.2f}".rstrip("0").rstrip(".")
                return f"{val} {unit}"
            n /= 1024.0
        return f"{n:.2f} PB"

    def format_target_status_brief(report: Dict[str, Any]) -> str:
        if not report:
            return "UNKNOWN"
        tags = report.get("tags_api") or {}
        if tags.get("success"):
            return "OK"
        if tags.get("is_unauthorized"):
            return "UNAUTHORIZED"
        return "FAILED"

    def init_duckdb(db_path: str) -> Any:
        return duckdb.connect(db_path)

    probe_target = None  # type: ignore
    save_target_to_duckdb = None  # type: ignore


# ============================================================================
# Database Query Engine
# ============================================================================

class DuckDBEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.lock = threading.Lock()
        if not HAS_DUCKDB:
            raise RuntimeError("DuckDB is not installed. Install via: pip install duckdb")
        # Ensure tables exist
        self.conn = init_duckdb(db_path)

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            cur = self.conn.cursor()
            total_targets = cur.execute("SELECT count(*) FROM targets").fetchone()[0]
            if total_targets == 0:
                return {
                    "total_targets": 0, "authorized": 0, "unauthorized": 0, "partial": 0,
                    "failed": 0, "total_models": 0, "unique_models": 0, "avg_latency_ms": 0.0,
                    "max_speed_tok_s": 0.0, "latest_scan": None, "top_models": []
                }

            authorized = cur.execute("SELECT count(*) FROM targets WHERE is_authorized = true").fetchone()[0]
            unauthorized = cur.execute("SELECT count(*) FROM targets WHERE is_unauthorized = true").fetchone()[0]
            partial = cur.execute("SELECT count(*) FROM targets WHERE chat_status = 'PARTIAL'").fetchone()[0]
            failed = cur.execute("SELECT count(*) FROM targets WHERE (tags_success = false AND openai_success = false)").fetchone()[0]
            total_models = cur.execute("SELECT count(*) FROM models").fetchone()[0]
            unique_models = cur.execute("SELECT count(DISTINCT name) FROM models").fetchone()[0]
            avg_lat = cur.execute("SELECT avg(latency_ms) FROM targets WHERE latency_ms IS NOT NULL").fetchone()[0] or 0.0
            max_speed = cur.execute("SELECT max(speed_tok_s) FROM targets WHERE speed_tok_s IS NOT NULL").fetchone()[0] or 0.0
            latest_scan = cur.execute("SELECT max(scanned_at) FROM targets").fetchone()[0]

            top_models_rows = cur.execute("""
                SELECT m.name, count(*) as cnt, sum(CASE WHEN t.is_authorized = true THEN 1 ELSE 0 END) as auth_cnt
                FROM models m
                LEFT JOIN targets t ON m.base_url = t.base_url
                GROUP BY m.name
                ORDER BY cnt DESC, m.name ASC
                LIMIT 10
            """).fetchall()

            top_models = [{"name": r[0], "count": r[1], "open_count": r[2] or 0} for r in top_models_rows]

            return {
                "total_targets": total_targets,
                "authorized": authorized,
                "unauthorized": unauthorized,
                "partial": partial,
                "failed": failed,
                "total_models": total_models,
                "unique_models": unique_models,
                "avg_latency_ms": round(float(avg_lat), 1),
                "max_speed_tok_s": round(float(max_speed), 1),
                "latest_scan": str(latest_scan) if latest_scan else None,
                "top_models": top_models,
                "db_path": self.db_path,
            }

    def get_targets(
        self,
        q: str = "",
        status: str = "all",
        model: str = "",
        port: Optional[int] = None,
        sort_by: str = "scanned_at",
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 25,
    ) -> Dict[str, Any]:
        with self.lock:
            cur = self.conn.cursor()
            where_clauses: List[str] = []
            params: List[Any] = []

            if q and q.strip():
                pattern = f"%{q.strip()}%"
                where_clauses.append("(target ILIKE ? OR host ILIKE ? OR status ILIKE ? OR version ILIKE ? OR models_list ILIKE ? OR error ILIKE ?)")
                params.extend([pattern, pattern, pattern, pattern, pattern, pattern])

            st = (status or "all").lower()
            if st in ("open", "authorized"):
                where_clauses.append("is_authorized = true")
            elif st == "unauthorized":
                where_clauses.append("is_unauthorized = true")
            elif st == "partial":
                where_clauses.append("chat_status = 'PARTIAL'")
            elif st in ("failed", "offline"):
                where_clauses.append("(tags_success = false AND openai_success = false)")
            elif st == "with_models":
                where_clauses.append("models_count > 0")
            elif st == "with_speed":
                where_clauses.append("speed_tok_s IS NOT NULL")

            if model and model.strip():
                where_clauses.append("models_list ILIKE ?")
                params.append(f"%{model.strip()}%")

            if port:
                where_clauses.append("port = ?")
                params.append(int(port))

            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            # Count matching total
            count_sql = f"SELECT count(*) FROM targets {where_sql}"
            total = cur.execute(count_sql, params).fetchone()[0]

            allowed_cols = {
                "scanned_at": "scanned_at",
                "host": "host",
                "port": "port",
                "status": "status",
                "models_count": "models_count",
                "latency_ms": "latency_ms",
                "speed_tok_s": "speed_tok_s",
            }
            order_col = allowed_cols.get(sort_by, "scanned_at")
            order_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

            page = max(1, int(page))
            page_size = max(1, min(500, int(page_size)))
            offset = (page - 1) * page_size

            query_sql = f"""
                SELECT base_url, target, host, port, scanned_at, status, version,
                       tags_success, openai_success, chat_status, is_authorized, is_unauthorized,
                       models_count, models_list, latency_ms, speed_tok_s, error
                FROM targets
                {where_sql}
                ORDER BY {order_col} {order_dir} NULLS LAST
                LIMIT ? OFFSET ?
            """
            rows = cur.execute(query_sql, params + [page_size, offset]).fetchall()

            items = []
            for r in rows:
                items.append({
                    "base_url": r[0],
                    "target": r[1],
                    "host": r[2],
                    "port": r[3],
                    "scanned_at": str(r[4]) if r[4] else None,
                    "status": r[5],
                    "version": r[6],
                    "tags_success": bool(r[7]),
                    "openai_success": bool(r[8]),
                    "chat_status": r[9],
                    "is_authorized": bool(r[10]),
                    "is_unauthorized": bool(r[11]),
                    "models_count": r[12] or 0,
                    "models_list": r[13] or "",
                    "latency_ms": round(float(r[14]), 1) if r[14] is not None else None,
                    "speed_tok_s": round(float(r[15]), 1) if r[15] is not None else None,
                    "error": r[16],
                })

            total_pages = max(1, (total + page_size - 1) // page_size)
            return {
                "targets": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
            }

    def get_target_detail(self, target_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            query = """
                SELECT base_url, target, host, port, scanned_at, status, version,
                       tags_success, openai_success, chat_status, is_authorized, is_unauthorized,
                       models_count, models_list, latency_ms, speed_tok_s, error, report_json
                FROM targets
                WHERE base_url = ? OR target = ? OR host = ?
                ORDER BY scanned_at DESC
                LIMIT 1
            """
            row = cur.execute(query, [target_id, target_id, target_id]).fetchone()
            if not row:
                return None

            base_url = row[0]
            models_rows = cur.execute("""
                SELECT name, model_id, size_bytes, parameter_size, quantization, format, family, modified_at
                FROM models
                WHERE base_url = ?
                ORDER BY name ASC
            """, [base_url]).fetchall()

            models = []
            for m in models_rows:
                models.append({
                    "name": m[0],
                    "model_id": m[1],
                    "size_bytes": m[2],
                    "size_formatted": format_bytes(m[2]) if m[2] else None,
                    "parameter_size": m[3] or "",
                    "quantization": m[4] or "",
                    "format": m[5] or "",
                    "family": m[6] or "",
                    "modified_at": str(m[7]) if m[7] else None,
                })

            report_obj = {}
            if row[17]:
                try:
                    report_obj = json.loads(row[17])
                except Exception:
                    report_obj = {}

            return {
                "base_url": row[0],
                "target": row[1],
                "host": row[2],
                "port": row[3],
                "scanned_at": str(row[4]) if row[4] else None,
                "status": row[5],
                "version": row[6],
                "tags_success": bool(row[7]),
                "openai_success": bool(row[8]),
                "chat_status": row[9],
                "is_authorized": bool(row[10]),
                "is_unauthorized": bool(row[11]),
                "models_count": row[12] or 0,
                "models_list": row[13] or "",
                "latency_ms": round(float(row[14]), 1) if row[14] is not None else None,
                "speed_tok_s": round(float(row[15]), 1) if row[15] is not None else None,
                "error": row[16],
                "models": models,
                "report": report_obj,
            }

    def get_models(
        self,
        q: str = "",
        grouped: bool = True,
        page: int = 1,
        page_size: int = 25,
    ) -> Dict[str, Any]:
        with self.lock:
            cur = self.conn.cursor()
            where: List[str] = []
            params: List[Any] = []
            if q and q.strip():
                pat = f"%{q.strip()}%"
                where.append("(m.name ILIKE ? OR m.family ILIKE ? OR m.parameter_size ILIKE ? OR m.quantization ILIKE ?)")
                params.extend([pat, pat, pat, pat])
            where_sql = ("WHERE " + " AND ".join(where)) if where else ""

            page = max(1, int(page))
            page_size = max(1, min(500, int(page_size)))
            offset = (page - 1) * page_size

            if grouped:
                count_sql = f"SELECT count(DISTINCT m.name) FROM models m {where_sql}"
                total = cur.execute(count_sql, params).fetchone()[0]

                sql = f"""
                    SELECT m.name,
                           count(*) as host_count,
                           sum(CASE WHEN t.is_authorized = true THEN 1 ELSE 0 END) as open_hosts,
                           max(m.size_bytes) as size_bytes,
                           max(m.parameter_size) as parameter_size,
                           max(m.quantization) as quantization,
                           max(m.format) as format,
                           max(m.family) as family,
                           string_agg(DISTINCT m.host, ', ') as hosts_sample
                    FROM models m
                    LEFT JOIN targets t ON m.base_url = t.base_url
                    {where_sql}
                    GROUP BY m.name
                    ORDER BY host_count DESC, m.name ASC
                    LIMIT ? OFFSET ?
                """
                rows = cur.execute(sql, params + [page_size, offset]).fetchall()
                items = []
                for r in rows:
                    items.append({
                        "name": r[0],
                        "host_count": r[1],
                        "open_hosts": r[2] or 0,
                        "size_bytes": r[3],
                        "size_formatted": format_bytes(r[3]) if r[3] else None,
                        "parameter_size": r[4] or "",
                        "quantization": r[5] or "",
                        "format": r[6] or "",
                        "family": r[7] or "",
                        "hosts_sample": r[8] or "",
                    })
            else:
                count_sql = f"SELECT count(*) FROM models m {where_sql}"
                total = cur.execute(count_sql, params).fetchone()[0]

                sql = f"""
                    SELECT m.base_url, m.target, m.host, m.port, m.name, m.model_id,
                           m.size_bytes, m.parameter_size, m.quantization, m.format, m.family,
                           t.is_authorized, t.status
                    FROM models m
                    LEFT JOIN targets t ON m.base_url = t.base_url
                    {where_sql}
                    ORDER BY m.name ASC, m.host ASC
                    LIMIT ? OFFSET ?
                """
                rows = cur.execute(sql, params + [page_size, offset]).fetchall()
                items = []
                for r in rows:
                    items.append({
                        "base_url": r[0],
                        "target": r[1],
                        "host": r[2],
                        "port": r[3],
                        "name": r[4],
                        "model_id": r[5],
                        "size_bytes": r[6],
                        "size_formatted": format_bytes(r[6]) if r[6] else None,
                        "parameter_size": r[7] or "",
                        "quantization": r[8] or "",
                        "format": r[9] or "",
                        "family": r[10] or "",
                        "is_authorized": bool(r[11]),
                        "target_status": r[12] or "UNKNOWN",
                    })

            total_pages = max(1, (total + page_size - 1) // page_size)
            return {
                "models": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
            }

    def execute_sql(self, sql: str, limit: int = 500) -> Dict[str, Any]:
        sql_clean = sql.strip()
        if not sql_clean:
            return {"error": "SQL query cannot be empty."}

        # Guard against disruptive admin operations in web console
        disallowed = ["PRAGMA", "ATTACH", "INSTALL", "LOAD", "COPY TO '/"]
        for kw in disallowed:
            if re.search(r'\b' + kw + r'\b', sql_clean, re.IGNORECASE):
                return {"error": f"Operation '{kw}' is restricted in the web SQL studio."}

        start = time.perf_counter()
        with self.lock:
            try:
                cur = self.conn.cursor()
                res = cur.execute(sql_clean)
                elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
                if res.description:
                    columns = [desc[0] for desc in res.description]
                    rows = res.fetchall()
                    formatted = []
                    for r in rows[:limit]:
                        formatted.append([
                            str(v) if v is not None and not isinstance(v, (int, float, bool)) else v
                            for v in r
                        ])
                    return {
                        "columns": columns,
                        "rows": formatted,
                        "row_count": len(rows),
                        "duration_ms": elapsed_ms,
                    }
                else:
                    self.conn.commit()
                    return {
                        "columns": [],
                        "rows": [],
                        "row_count": 0,
                        "duration_ms": elapsed_ms,
                        "message": "Query executed successfully (no rows returned).",
                    }
            except Exception as e:
                return {"error": str(e)}

    def probe_and_save_target(
        self,
        target: str,
        port: int = 11434,
        use_https: bool = False,
        api_key: Optional[str] = None,
        run_speed: bool = False,
    ) -> Dict[str, Any]:
        if not probe_target or not save_target_to_duckdb:
            return {"success": False, "error": "Probe functionality not loaded from ollama_cli.py"}

        try:
            report = probe_target(
                target=target,
                default_port=port,
                use_https=use_https,
                api_key=api_key,
                run_speed=run_speed,
                timeout=10.0,
            )
            with self.lock:
                save_target_to_duckdb(self.conn, report)
            return {"success": True, "report": report}
        except Exception as e:
            return {"success": False, "error": str(e)}


# ============================================================================
# HTTP Request Handler & REST API
# ============================================================================

class DashboardHandler(BaseHTTPRequestHandler):
    engine: DuckDBEngine  # injected by server

    def _send_json(self, data: Any, status_code: int = 200) -> None:
        payload = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, text: str, content_type: str = "text/plain; charset=utf-8", status_code: int = 200, filename: Optional[str] = None) -> None:
        payload = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if filename:
            self.send_header("Content-Disposition", f"attachment; filename=\"{filename}\"")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = urllib.parse.parse_qs(parsed.query)

        # Single Page Application Frontend
        if path in ("", "/", "/index.html"):
            self._send_text(DASHBOARD_HTML, content_type="text/html; charset=utf-8")
            return

        # REST APIs
        if path == "/api/stats":
            stats = self.engine.get_stats()
            self._send_json(stats)
            return

        if path == "/api/targets":
            q = query.get("q", [""])[0]
            status = query.get("status", ["all"])[0]
            model = query.get("model", [""])[0]
            port_str = query.get("port", [""])[0]
            port = int(port_str) if port_str.isdigit() else None
            sort_by = query.get("sort_by", ["scanned_at"])[0]
            sort_dir = query.get("sort_dir", ["desc"])[0]
            page = int(query.get("page", ["1"])[0])
            page_size = int(query.get("page_size", ["25"])[0])

            res = self.engine.get_targets(
                q=q, status=status, model=model, port=port,
                sort_by=sort_by, sort_dir=sort_dir, page=page, page_size=page_size
            )
            self._send_json(res)
            return

        if path.startswith("/api/targets/"):
            target_key = urllib.parse.unquote(path[len("/api/targets/"):])
            detail = self.engine.get_target_detail(target_key)
            if detail:
                self._send_json(detail)
            else:
                self._send_json({"error": "Target not found"}, status_code=404)
            return

        if path == "/api/models":
            q = query.get("q", [""])[0]
            grouped = query.get("grouped", ["true"])[0].lower() in ("true", "1", "yes")
            page = int(query.get("page", ["1"])[0])
            page_size = int(query.get("page_size", ["25"])[0])

            res = self.engine.get_models(q=q, grouped=grouped, page=page, page_size=page_size)
            self._send_json(res)
            return

        if path == "/api/export":
            fmt = query.get("format", ["txt"])[0].lower()
            q = query.get("q", [""])[0]
            status = query.get("status", ["all"])[0]
            model = query.get("model", [""])[0]
            port_str = query.get("port", [""])[0]
            port = int(port_str) if port_str.isdigit() else None

            res = self.engine.get_targets(
                q=q, status=status, model=model, port=port,
                page=1, page_size=100000
            )
            targets = res["targets"]

            if fmt == "json":
                self._send_text(
                    json.dumps(targets, indent=2, default=str),
                    content_type="application/json; charset=utf-8",
                    filename=f"ollama_targets_{int(time.time())}.json"
                )
            elif fmt == "csv":
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(["host", "port", "base_url", "status", "version", "models_count", "models_list", "is_authorized", "latency_ms", "speed_tok_s", "scanned_at"])
                for t in targets:
                    writer.writerow([
                        t["host"], t["port"], t["base_url"], t["status"], t["version"],
                        t["models_count"], t["models_list"], t["is_authorized"], t["latency_ms"], t["speed_tok_s"], t["scanned_at"]
                    ])
                self._send_text(
                    buf.getvalue(),
                    content_type="text/csv; charset=utf-8",
                    filename=f"ollama_targets_{int(time.time())}.csv"
                )
            else:
                # Plain IP list (ideal for piping or feeding to -f)
                lines = [f"{t['host']}:{t['port']}" for t in targets]
                self._send_text(
                    "\n".join(lines) + "\n",
                    content_type="text/plain; charset=utf-8",
                    filename=f"targets_{int(time.time())}.txt"
                )
            return

        self._send_json({"error": "Endpoint not found"}, status_code=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        content_len = int(self.headers.get("Content-Length", 0))
        post_bytes = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            payload = json.loads(post_bytes.decode("utf-8")) if post_bytes else {}
        except Exception:
            self._send_json({"error": "Invalid JSON body"}, status_code=400)
            return

        if path == "/api/query":
            sql = payload.get("query", "")
            limit = int(payload.get("limit", 500))
            result = self.engine.execute_sql(sql, limit=limit)
            status_code = 400 if "error" in result else 200
            self._send_json(result, status_code=status_code)
            return

        if path == "/api/probe":
            target = payload.get("target", "").strip()
            if not target:
                self._send_json({"error": "Target IP/host required"}, status_code=400)
                return
            port = int(payload.get("port", 11434))
            use_https = bool(payload.get("use_https", False))
            api_key = payload.get("api_key") or None
            run_speed = bool(payload.get("run_speed", False))

            res = self.engine.probe_and_save_target(
                target=target, port=port, use_https=use_https,
                api_key=api_key, run_speed=run_speed
            )
            self._send_json(res, status_code=200 if res.get("success") else 500)
            return

        self._send_json({"error": "Endpoint not found"}, status_code=404)

    def log_message(self, format, *args):
        # Silence standard HTTP access logs to keep console clean, unless requested
        if os.getenv("DASHBOARD_DEBUG"):
            sys.stderr.write(f"[HTTP] {self.address_string()} - {format % args}\n")


# ============================================================================
# Web Dashboard Single-Page Application (HTML/CSS/JS)
# ============================================================================

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ollama DuckDB Explorer & Security Dashboard</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-hover: #172033;
      --border: #1e293b;
      --border-light: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --cyan: #06b6d4;
      --cyan-glow: rgba(6, 182, 212, 0.2);
      --emerald: #10b981;
      --emerald-glow: rgba(16, 185, 129, 0.2);
      --amber: #f59e0b;
      --amber-glow: rgba(245, 158, 11, 0.2);
      --rose: #f43f5e;
      --rose-glow: rgba(244, 63, 94, 0.2);
      --indigo: #6366f1;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      --mono: "SF Mono", Monaco, Inconsolata, "Fira Code", monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      line-height: 1.5;
      font-size: 14px;
      overflow-x: hidden;
    }
    /* Layout */
    .container { max-width: 1440px; margin: 0 auto; padding: 20px; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-logo {
      background: linear-gradient(135deg, var(--cyan), var(--indigo));
      width: 40px; height: 40px; border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 20px; font-weight: bold; color: #fff;
      box-shadow: 0 0 20px var(--cyan-glow);
    }
    .brand-text h1 { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
    .brand-text p { font-size: 12px; color: var(--text-muted); }
    .header-actions { display: flex; gap: 10px; align-items: center; }

    /* Badges & Buttons */
    .btn {
      background: #1e293b; color: var(--text); border: 1px solid var(--border);
      padding: 7px 14px; border-radius: 6px; font-size: 13px; font-weight: 500;
      cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
      transition: all 0.15s ease;
    }
    .btn:hover { background: #334155; border-color: var(--border-light); }
    .btn-primary {
      background: linear-gradient(135deg, #0891b2, #0284c7);
      border-color: #0ea5e9; color: #fff;
    }
    .btn-primary:hover { background: linear-gradient(135deg, #06b6d4, #0369a1); }
    .btn-emerald { background: rgba(16, 185, 129, 0.15); color: #34d399; border-color: rgba(16, 185, 129, 0.3); }
    .btn-emerald:hover { background: rgba(16, 185, 129, 0.25); }

    /* Stat Cards */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px; margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 10px; padding: 16px; position: relative;
      overflow: hidden; transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .stat-card:hover { border-color: var(--border-light); transform: translateY(-2px); }
    .stat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .stat-title { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
    .stat-value { font-size: 28px; font-weight: 800; letter-spacing: -0.03em; color: #fff; }
    .stat-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; display: flex; align-items: center; gap: 6px; }

    /* Nav Tabs */
    .tabs-bar {
      display: flex; gap: 4px; border-bottom: 1px solid var(--border);
      margin-bottom: 20px; overflow-x: auto;
    }
    .tab-btn {
      background: transparent; color: var(--text-muted); border: none;
      padding: 10px 18px; font-size: 13px; font-weight: 600; cursor: pointer;
      border-bottom: 2px solid transparent; display: flex; align-items: center; gap: 8px;
      transition: all 0.15s; white-space: nowrap;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active { color: var(--cyan); border-bottom-color: var(--cyan); }

    /* Filter & Search Bar */
    .filter-panel {
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 8px; padding: 14px 16px; margin-bottom: 16px;
      display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
      justify-content: space-between;
    }
    .search-box {
      flex: 1; min-width: 260px; position: relative; display: flex; align-items: center;
    }
    .search-box input {
      width: 100%; background: #0b1120; border: 1px solid var(--border);
      border-radius: 6px; padding: 8px 12px 8px 34px; color: var(--text);
      font-size: 13px; outline: none; transition: border-color 0.15s;
    }
    .search-box input:focus { border-color: var(--cyan); box-shadow: 0 0 0 2px var(--cyan-glow); }
    .search-icon { position: absolute; left: 10px; color: var(--text-muted); pointer-events: none; }

    .filter-group { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .filter-chip {
      background: #1e293b; color: var(--text-muted); border: 1px solid transparent;
      padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 500;
      cursor: pointer; transition: all 0.15s;
    }
    .filter-chip:hover { color: var(--text); background: #334155; }
    .filter-chip.active { background: rgba(6, 182, 212, 0.15); color: #22d3ee; border-color: rgba(6, 182, 212, 0.3); font-weight: 600; }
    .filter-chip.open-active { background: rgba(16, 185, 129, 0.15); color: #34d399; border-color: rgba(16, 185, 129, 0.3); }
    .filter-chip.unauth-active { background: rgba(244, 63, 94, 0.15); color: #fb7185; border-color: rgba(244, 63, 94, 0.3); }

    select.input-select {
      background: #0b1120; color: var(--text); border: 1px solid var(--border);
      border-radius: 6px; padding: 7px 10px; font-size: 12px; outline: none; cursor: pointer;
    }
    select.input-select:focus { border-color: var(--cyan); }

    /* Table */
    .table-container {
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 8px; overflow: hidden; margin-bottom: 16px;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th {
      background: #0f172a; color: var(--text-muted); font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.05em; padding: 10px 14px;
      border-bottom: 1px solid var(--border); font-weight: 600;
    }
    td { padding: 12px 14px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: var(--card-hover); }

    /* Badges */
    .badge {
      display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px;
      border-radius: 4px; font-size: 11px; font-weight: 600; letter-spacing: 0.02em;
    }
    .badge-open { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-unauth { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }
    .badge-partial { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-offline { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.25); }
    .badge-speed { background: rgba(6, 182, 212, 0.15); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.3); font-family: var(--mono); }
    .badge-count { background: #1e293b; color: #e2e8f0; padding: 2px 6px; border-radius: 12px; font-size: 11px; font-family: var(--mono); }

    .host-link { font-family: var(--mono); font-weight: 600; color: #38bdf8; text-decoration: none; }
    .host-link:hover { text-decoration: underline; }

    /* Pagination */
    .pagination-bar {
      display: flex; justify-content: space-between; align-items: center;
      padding: 10px 4px; font-size: 13px; color: var(--text-muted);
    }
    .page-controls { display: flex; gap: 6px; align-items: center; }

    /* SQL Studio */
    .sql-editor {
      width: 100%; height: 120px; background: #080c14; border: 1px solid var(--border);
      border-radius: 6px; padding: 12px; color: #38bdf8; font-family: var(--mono);
      font-size: 13px; line-height: 1.4; outline: none; margin-bottom: 12px; resize: vertical;
    }
    .sql-editor:focus { border-color: var(--cyan); box-shadow: 0 0 0 2px var(--cyan-glow); }
    .sql-presets { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }

    /* Modal / Inspector */
    .modal-backdrop {
      position: fixed; inset: 0; background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px); display: none; align-items: center;
      justify-content: center; z-index: 999; padding: 20px;
    }
    .modal-card {
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 12px; width: 100%; max-width: 860px; max-height: 90vh;
      display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.6);
    }
    .modal-header {
      padding: 16px 20px; border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center;
    }
    .modal-body { padding: 20px; overflow-y: auto; flex: 1; }
    .json-pre {
      background: #080c14; border: 1px solid var(--border); border-radius: 6px;
      padding: 14px; color: #38bdf8; font-family: var(--mono); font-size: 12px;
      max-height: 360px; overflow: auto; white-space: pre-wrap; word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="brand">
        <div class="brand-logo">🦆</div>
        <div class="brand-text">
          <h1>Ollama DuckDB Explorer</h1>
          <p id="db-badge">Database: <span style="color:var(--cyan);font-family:var(--mono);">loading...</span></p>
        </div>
      </div>
      <div class="header-actions">
        <button class="btn" onclick="fetchStats(); fetchTargets();">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
          Refresh
        </button>
        <button class="btn btn-primary" onclick="switchTab('probe')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m10 8 4 4-4 4"/></svg>
          Live Probe
        </button>
      </div>
    </header>

    <!-- Top KPI Stat Cards -->
    <div class="stats-grid">
      <div class="stat-card" style="border-top: 3px solid var(--cyan);">
        <div class="stat-header">
          <span class="stat-title">Total Scanned Targets</span>
          <span class="badge badge-speed" id="stat-latency">-- ms avg</span>
        </div>
        <div class="stat-value" id="stat-total">0</div>
        <div class="stat-sub" id="stat-latest">Last scan: calculating...</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--emerald);">
        <div class="stat-header">
          <span class="stat-title">Open Chat (Authorized)</span>
          <span class="badge badge-open">OPEN</span>
        </div>
        <div class="stat-value" style="color: #34d399;" id="stat-auth">0</div>
        <div class="stat-sub" id="stat-auth-pct">0% of targets</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--rose);">
        <div class="stat-header">
          <span class="stat-title">Protected / Unauthorized</span>
          <span class="badge badge-unauth">401 / 403</span>
        </div>
        <div class="stat-value" style="color: #fb7185;" id="stat-unauth">0</div>
        <div class="stat-sub" id="stat-unauth-pct">0% of targets</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--amber);">
        <div class="stat-header">
          <span class="stat-title">Discovered Models</span>
          <span class="badge badge-speed" id="stat-max-speed">-- tok/s max</span>
        </div>
        <div class="stat-value" style="color: #fbbf24;" id="stat-models">0</div>
        <div class="stat-sub" id="stat-instances">0 total instances recorded</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-bar">
      <button class="tab-btn active" id="tab-targets-btn" onclick="switchTab('targets')">
        🎯 Targets Explorer
      </button>
      <button class="tab-btn" id="tab-models-btn" onclick="switchTab('models')">
        🤖 Models Registry
      </button>
      <button class="tab-btn" id="tab-sql-btn" onclick="switchTab('sql')">
        💻 DuckDB SQL Studio
      </button>
      <button class="tab-btn" id="tab-probe-btn" onclick="switchTab('probe')">
        ⚡ Live Target Prober
      </button>
    </div>

    <!-- TAB 1: Targets Explorer -->
    <div id="tab-targets" class="tab-content">
      <div class="filter-panel">
        <div class="search-box">
          <span class="search-icon">🔍</span>
          <input type="text" id="target-search" placeholder="Search target IP, hostname, status, models, or error..." oninput="debounce(fetchTargets, 250)()">
        </div>
        <div class="filter-group">
          <button class="filter-chip active" data-status="all" onclick="setStatusFilter('all')">All</button>
          <button class="filter-chip" data-status="open" onclick="setStatusFilter('open')">Authorized (Open)</button>
          <button class="filter-chip" data-status="unauthorized" onclick="setStatusFilter('unauthorized')">Unauthorized</button>
          <button class="filter-chip" data-status="partial" onclick="setStatusFilter('partial')">Partial</button>
          <button class="filter-chip" data-status="failed" onclick="setStatusFilter('failed')">Offline/Failed</button>
          <button class="filter-chip" data-status="with_speed" onclick="setStatusFilter('with_speed')">⚡ Speed Benchmarked</button>
        </div>
        <div class="filter-group">
          <select id="sort-select" class="input-select" onchange="fetchTargets()">
            <option value="scanned_at:desc">Latest Scanned</option>
            <option value="models_count:desc">Most Models</option>
            <option value="speed_tok_s:desc">Highest Speed (tok/s)</option>
            <option value="latency_ms:asc">Lowest Latency (ms)</option>
            <option value="host:asc">Host IP (Asc)</option>
          </select>
          <select id="export-select" class="input-select" onchange="exportCurrent(this.value); this.value='';">
            <option value="">Export Targets...</option>
            <option value="txt">IPs (Plain TXT)</option>
            <option value="csv">Summary (CSV)</option>
            <option value="json">Full Records (JSON)</option>
          </select>
        </div>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Target Host</th>
              <th>Status & Auth</th>
              <th>Version</th>
              <th>Models</th>
              <th>APIs Supported</th>
              <th>Speed / Latency</th>
              <th>Scanned At</th>
              <th style="text-align: right;">Action</th>
            </tr>
          </thead>
          <tbody id="targets-table-body">
            <tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted);">Loading targets from DuckDB...</td></tr>
          </tbody>
        </table>
      </div>

      <div class="pagination-bar">
        <span id="pagination-info">Showing 0-0 of 0 targets</span>
        <div class="page-controls">
          <button class="btn" id="prev-page-btn" onclick="changePage(-1)">← Previous</button>
          <span id="current-page-display" style="padding:0 8px;font-weight:600;">Page 1</span>
          <button class="btn" id="next-page-btn" onclick="changePage(1)">Next →</button>
        </div>
      </div>
    </div>

    <!-- TAB 2: Models Registry -->
    <div id="tab-models" class="tab-content" style="display:none;">
      <div class="filter-panel">
        <div class="search-box">
          <span class="search-icon">🔍</span>
          <input type="text" id="model-search" placeholder="Search model name, family (e.g. llama, qwen, mistral), parameter size..." oninput="debounce(fetchModels, 250)()">
        </div>
        <div class="filter-group">
          <label style="font-size:12px;color:var(--text-muted);display:flex;align-items:center;gap:6px;cursor:pointer;">
            <input type="checkbox" id="models-grouped-check" checked onchange="fetchModels()">
            Group by Model Name
          </label>
        </div>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Model Name</th>
              <th>Family</th>
              <th>Parameters</th>
              <th>Quantization</th>
              <th>Size</th>
              <th>Host Count</th>
              <th>Open / Authorized Hosts</th>
              <th style="text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody id="models-table-body">
            <tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted);">Loading models registry...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: SQL Studio -->
    <div id="tab-sql" class="tab-content" style="display:none;">
      <div class="filter-panel" style="flex-direction:column;align-items:stretch;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-weight:600;font-size:13px;">DuckDB SQL Studio Console</span>
          <div style="display:flex;gap:8px;">
            <button class="btn btn-primary" onclick="runSqlQuery()">▶ Run Query (Ctrl+Enter)</button>
          </div>
        </div>
        <textarea id="sql-input" class="sql-editor" placeholder="SELECT * FROM targets WHERE is_authorized = true LIMIT 50">SELECT * FROM targets WHERE is_authorized = true LIMIT 50;</textarea>
        <div class="sql-presets">
          <span style="font-size:11px;color:var(--text-muted);align-self:center;">Presets:</span>
          <button class="filter-chip" onclick="setSqlPreset('open_targets')">All Open Targets</button>
          <button class="filter-chip" onclick="setSqlPreset('top_models')">Top 20 Models by Count</button>
          <button class="filter-chip" onclick="setSqlPreset('fastest_hosts')">Fastest Hosts (tok/s)</button>
          <button class="filter-chip" onclick="setSqlPreset('unauth_hosts')">Unauthorized Hosts</button>
          <button class="filter-chip" onclick="setSqlPreset('models_summary')">Models Summary by Family</button>
        </div>
      </div>

      <div id="sql-meta-bar" style="margin-bottom:8px;font-size:12px;color:var(--text-muted);display:none;"></div>
      <div class="table-container" id="sql-results-container" style="display:none;max-height:450px;overflow:auto;">
        <table id="sql-results-table">
          <thead id="sql-results-head"></thead>
          <tbody id="sql-results-body"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 4: Live Target Prober -->
    <div id="tab-probe" class="tab-content" style="display:none;">
      <div class="filter-panel" style="max-width:640px;margin:0 auto 24px auto;">
        <h3 style="margin-bottom:12px;font-size:15px;width:100%;">Probe Single Ollama Target & Update DuckDB</h3>
        <div style="display:flex;flex-direction:column;gap:12px;width:100%;">
          <div>
            <label style="font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px;">Target IP / Host</label>
            <input type="text" id="probe-target-input" class="input-select" style="width:100%;padding:10px;" placeholder="e.g. 127.0.0.1 or 192.168.1.50">
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px;">Port</label>
              <input type="number" id="probe-port-input" class="input-select" style="width:100%;padding:10px;" value="11434">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px;">Optional API Key</label>
              <input type="password" id="probe-key-input" class="input-select" style="width:100%;padding:10px;" placeholder="Bearer token if required">
            </div>
          </div>
          <div style="display:flex;gap:16px;margin-top:4px;">
            <label style="font-size:12px;color:var(--text);display:flex;align-items:center;gap:6px;cursor:pointer;">
              <input type="checkbox" id="probe-speed-check"> Run Chat Speed Benchmark
            </label>
            <label style="font-size:12px;color:var(--text);display:flex;align-items:center;gap:6px;cursor:pointer;">
              <input type="checkbox" id="probe-https-check"> Use HTTPS
            </label>
          </div>
          <button class="btn btn-primary" style="justify-content:center;padding:12px;margin-top:8px;" onclick="runLiveProbe()">
            ⚡ Probe Host & Save to DuckDB
          </button>
        </div>
      </div>
      <div id="probe-result-box" style="display:none;max-width:800px;margin:0 auto;"></div>
    </div>
  </div>

  <!-- Detail / Inspect Modal -->
  <div class="modal-backdrop" id="inspect-modal" onclick="if(event.target === this) closeModal();">
    <div class="modal-card">
      <div class="modal-header">
        <div style="display:flex;align-items:center;gap:10px;">
          <h2 id="modal-title" style="font-size:16px;font-family:var(--mono);">Target Details</h2>
          <span id="modal-status-badge"></span>
        </div>
        <button class="btn" onclick="closeModal()">✕</button>
      </div>
      <div class="modal-body" id="modal-body-content">
        <!-- Content filled dynamically -->
      </div>
    </div>
  </div>

  <script>
    // State management
    let currentTab = 'targets';
    let currentStatus = 'all';
    let currentPage = 1;
    let pageSize = 25;
    let totalTargets = 0;

    function debounce(func, wait) {
      let timeout;
      return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
      };
    }

    function switchTab(tab) {
      currentTab = tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
      document.getElementById(`tab-${tab}-btn`).classList.add('active');
      document.getElementById(`tab-${tab}`).style.display = 'block';

      if (tab === 'targets') fetchTargets();
      if (tab === 'models') fetchModels();
    }

    function setStatusFilter(st) {
      currentStatus = st;
      document.querySelectorAll('.filter-chip[data-status]').forEach(c => {
        c.classList.toggle('active', c.getAttribute('data-status') === st);
      });
      currentPage = 1;
      fetchTargets();
    }

    // Load initial stats
    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('stat-total').textContent = data.total_targets.toLocaleString();
        document.getElementById('stat-auth').textContent = data.authorized.toLocaleString();
        document.getElementById('stat-unauth').textContent = data.unauthorized.toLocaleString();
        document.getElementById('stat-models').textContent = data.unique_models.toLocaleString();
        document.getElementById('stat-latency').textContent = `${data.avg_latency_ms}ms avg`;
        document.getElementById('stat-max-speed').textContent = `${data.max_speed_tok_s} tok/s max`;
        document.getElementById('stat-instances').textContent = `${data.total_models.toLocaleString()} instances recorded`;

        const authPct = data.total_targets ? ((data.authorized / data.total_targets) * 100).toFixed(1) : 0;
        const unauthPct = data.total_targets ? ((data.unauthorized / data.total_targets) * 100).toFixed(1) : 0;
        document.getElementById('stat-auth-pct').textContent = `${authPct}% of all targets`;
        document.getElementById('stat-unauth-pct').textContent = `${unauthPct}% of all targets`;

        if (data.latest_scan) {
          const dt = new Date(data.latest_scan);
          document.getElementById('stat-latest').textContent = `Latest scan: ${dt.toLocaleTimeString()} (${dt.toLocaleDateString()})`;
        }
        if (data.db_path) {
          document.getElementById('db-badge').innerHTML = `Database: <span style="color:var(--cyan);font-family:var(--mono);">${data.db_path}</span>`;
        }
      } catch (err) {
        console.error("Failed to load stats:", err);
      }
    }

    // Load targets
    async function fetchTargets() {
      const q = document.getElementById('target-search').value;
      const sortVal = document.getElementById('sort-select').value.split(':');
      const sortBy = sortVal[0] || 'scanned_at';
      const sortDir = sortVal[1] || 'desc';

      const url = `/api/targets?q=${encodeURIComponent(q)}&status=${encodeURIComponent(currentStatus)}&sort_by=${sortBy}&sort_dir=${sortDir}&page=${currentPage}&page_size=${pageSize}`;
      const tbody = document.getElementById('targets-table-body');
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--text-muted);">Fetching matching targets...</td></tr>';

      try {
        const res = await fetch(url);
        const data = await res.json();
        totalTargets = data.total;
        renderTargetsTable(data.targets);

        const startIdx = totalTargets === 0 ? 0 : (data.page - 1) * data.page_size + 1;
        const endIdx = Math.min(totalTargets, data.page * data.page_size);
        document.getElementById('pagination-info').textContent = `Showing ${startIdx}-${endIdx} of ${totalTargets.toLocaleString()} targets`;
        document.getElementById('current-page-display').textContent = `Page ${data.page} of ${data.total_pages}`;
        document.getElementById('prev-page-btn').disabled = data.page <= 1;
        document.getElementById('next-page-btn').disabled = data.page >= data.total_pages;
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--rose);">Error loading targets: ${err.message}</td></tr>`;
      }
    }

    function renderTargetsTable(targets) {
      const tbody = document.getElementById('targets-table-body');
      if (!targets || targets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted);">No matching Ollama targets found in DuckDB.</td></tr>';
        return;
      }

      tbody.innerHTML = targets.map(t => {
        let authBadge = '<span class="badge badge-offline">UNKNOWN</span>';
        if (t.is_authorized) {
          authBadge = '<span class="badge badge-open">OPEN (AUTH OK)</span>';
        } else if (t.is_unauthorized) {
          authBadge = '<span class="badge badge-unauth">UNAUTHORIZED</span>';
        } else if (t.chat_status === 'PARTIAL') {
          authBadge = '<span class="badge badge-partial">PARTIAL AUTH</span>';
        }

        const modelsCountBadge = `<span class="badge-count">${t.models_count}</span>`;
        const speedBadge = t.speed_tok_s ? `<span class="badge badge-speed">${t.speed_tok_s} t/s</span>` : '';
        const latencyStr = t.latency_ms ? `${t.latency_ms}ms` : '--';

        return `
          <tr>
            <td>
              <a href="${t.base_url}" target="_blank" class="host-link">${t.host}:${t.port}</a>
            </td>
            <td>
              <div style="display:flex;flex-direction:column;gap:3px;">
                ${authBadge}
                <span style="font-size:11px;color:var(--text-muted);">${escapeHtml(t.status || '')}</span>
              </div>
            </td>
            <td>${t.version ? `<span style="font-family:var(--mono);font-size:12px;">v${escapeHtml(t.version)}</span>` : '<span style="color:var(--text-muted)">—</span>'}</td>
            <td>
              <div style="display:flex;align-items:center;gap:6px;">
                ${modelsCountBadge}
                <span style="font-size:11px;color:var(--text-muted);max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${escapeHtml(t.models_list)}">
                  ${escapeHtml(t.models_list || 'None')}
                </span>
              </div>
            </td>
            <td>
              <div style="display:flex;gap:4px;">
                <span class="badge ${t.tags_success ? 'badge-open' : 'badge-offline'}">tags</span>
                <span class="badge ${t.openai_success ? 'badge-open' : 'badge-offline'}">v1</span>
              </div>
            </td>
            <td>
              <div style="display:flex;flex-direction:column;gap:2px;">
                ${speedBadge}
                <span style="font-size:11px;color:var(--text-muted);font-family:var(--mono);">${latencyStr}</span>
              </div>
            </td>
            <td style="font-size:11px;color:var(--text-muted);white-space:nowrap;">
              ${t.scanned_at ? t.scanned_at.split('.')[0].replace('T', ' ') : '—'}
            </td>
            <td style="text-align: right;">
              <button class="btn" style="padding:4px 8px;font-size:11px;" onclick="inspectTarget('${encodeURIComponent(t.base_url)}')">Inspect</button>
            </td>
          </tr>
        `;
      }).join('');
    }

    function changePage(delta) {
      currentPage = Math.max(1, currentPage + delta);
      fetchTargets();
    }

    async function inspectTarget(targetKey) {
      const modal = document.getElementById('inspect-modal');
      const body = document.getElementById('modal-body-content');
      modal.style.display = 'flex';
      body.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted);">Loading target inspector...</div>';

      try {
        const res = await fetch(`/api/targets/${targetKey}`);
        const data = await res.json();
        document.getElementById('modal-title').textContent = `${data.host}:${data.port}`;

        let statusBadge = data.is_authorized
          ? '<span class="badge badge-open">AUTHORIZED / OPEN</span>'
          : (data.is_unauthorized ? '<span class="badge badge-unauth">UNAUTHORIZED</span>' : '<span class="badge badge-offline">FAILED</span>');
        document.getElementById('modal-status-badge').innerHTML = statusBadge;

        let modelsHtml = '<p style="color:var(--text-muted);">No models recorded for this host.</p>';
        if (data.models && data.models.length > 0) {
          modelsHtml = `
            <table style="margin-top:8px;">
              <thead>
                <tr>
                  <th>Model Name</th>
                  <th>Parameters</th>
                  <th>Quantization</th>
                  <th>Format</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                ${data.models.map(m => `
                  <tr>
                    <td style="font-family:var(--mono);font-weight:600;color:#38bdf8;">${escapeHtml(m.name)}</td>
                    <td>${escapeHtml(m.parameter_size || '—')}</td>
                    <td>${escapeHtml(m.quantization || '—')}</td>
                    <td>${escapeHtml(m.format || 'gguf')}</td>
                    <td>${m.size_formatted || '—'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
        }

        body.innerHTML = `
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:12px;margin-bottom:20px;">
            <div style="background:#080c14;padding:12px;border-radius:6px;border:1px solid var(--border);">
              <div style="font-size:11px;color:var(--text-muted);">BASE URL</div>
              <div style="font-family:var(--mono);font-size:13px;font-weight:600;"><a href="${data.base_url}" target="_blank" style="color:var(--cyan);">${data.base_url}</a></div>
            </div>
            <div style="background:#080c14;padding:12px;border-radius:6px;border:1px solid var(--border);">
              <div style="font-size:11px;color:var(--text-muted);">VERSION</div>
              <div style="font-family:var(--mono);font-size:13px;font-weight:600;">${data.version ? 'v' + data.version : 'Unknown'}</div>
            </div>
            <div style="background:#080c14;padding:12px;border-radius:6px;border:1px solid var(--border);">
              <div style="font-size:11px;color:var(--text-muted);">LATENCY / SPEED</div>
              <div style="font-family:var(--mono);font-size:13px;font-weight:600;">${data.latency_ms ? data.latency_ms + 'ms' : '--'} | ${data.speed_tok_s ? data.speed_tok_s + ' tok/s' : '--'}</div>
            </div>
            <div style="background:#080c14;padding:12px;border-radius:6px;border:1px solid var(--border);">
              <div style="font-size:11px;color:var(--text-muted);">MODELS COUNT</div>
              <div style="font-family:var(--mono);font-size:13px;font-weight:600;">${data.models_count} models</div>
            </div>
          </div>

          <h4 style="font-size:13px;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);">Recorded Models (${data.models ? data.models.length : 0})</h4>
          <div class="table-container" style="max-height:220px;overflow:auto;margin-bottom:20px;">
            ${modelsHtml}
          </div>

          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <h4 style="font-size:13px;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);">Serialized Report JSON</h4>
            <button class="btn" style="padding:3px 8px;font-size:11px;" onclick="copyJson()">📋 Copy JSON</button>
          </div>
          <pre class="json-pre" id="modal-json">${escapeHtml(JSON.stringify(data.report || data, null, 2))}</pre>
        `;
      } catch (err) {
        body.innerHTML = `<p style="color:var(--rose);">Error loading target detail: ${err.message}</p>`;
      }
    }

    function closeModal() {
      document.getElementById('inspect-modal').style.display = 'none';
    }

    function copyJson() {
      const text = document.getElementById('modal-json').textContent;
      navigator.clipboard.writeText(text);
      alert('JSON copied to clipboard!');
    }

    // Models Registry Tab
    async function fetchModels() {
      const q = document.getElementById('model-search').value;
      const grouped = document.getElementById('models-grouped-check').checked;
      const url = `/api/models?q=${encodeURIComponent(q)}&grouped=${grouped}&page=1&page_size=100`;

      const tbody = document.getElementById('models-table-body');
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--text-muted);">Loading models registry...</td></tr>';

      try {
        const res = await fetch(url);
        const data = await res.json();
        if (!data.models || data.models.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted);">No models found in DuckDB.</td></tr>';
          return;
        }

        tbody.innerHTML = data.models.map(m => `
          <tr>
            <td style="font-family:var(--mono);font-weight:700;color:#38bdf8;">${escapeHtml(m.name)}</td>
            <td>${m.family ? `<span class="badge badge-speed">${escapeHtml(m.family)}</span>` : '—'}</td>
            <td>${escapeHtml(m.parameter_size || '—')}</td>
            <td>${escapeHtml(m.quantization || '—')}</td>
            <td>${m.size_formatted || '—'}</td>
            <td><span class="badge-count" style="font-size:12px;">${m.host_count} hosts</span></td>
            <td><span class="badge badge-open">${m.open_hosts} open</span></td>
            <td style="text-align:right;">
              <button class="btn" style="padding:4px 8px;font-size:11px;" onclick="filterByModel('${encodeURIComponent(m.name)}')">View Hosts</button>
            </td>
          </tr>
        `).join('');
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--rose);">Error loading models: ${err.message}</td></tr>`;
      }
    }

    function filterByModel(modelName) {
      modelName = decodeURIComponent(modelName);
      switchTab('targets');
      document.getElementById('target-search').value = modelName;
      fetchTargets();
    }

    // SQL Studio Tab
    const SQL_PRESETS = {
      open_targets: "SELECT host, port, status, models_count, speed_tok_s, version FROM targets WHERE is_authorized = true ORDER BY models_count DESC LIMIT 50;",
      top_models: "SELECT name, count(*) as hosts_count, sum(CASE WHEN is_authorized = true THEN 1 ELSE 0 END) as open_hosts FROM models m JOIN targets t ON m.base_url = t.base_url GROUP BY name ORDER BY hosts_count DESC LIMIT 20;",
      fastest_hosts: "SELECT host, port, speed_tok_s, models_count, status FROM targets WHERE speed_tok_s IS NOT NULL ORDER BY speed_tok_s DESC LIMIT 25;",
      unauth_hosts: "SELECT host, port, status, version, error FROM targets WHERE is_unauthorized = true LIMIT 50;",
      models_summary: "SELECT family, count(*) as total_instances, count(DISTINCT name) as unique_models FROM models WHERE family != '' GROUP BY family ORDER BY total_instances DESC;"
    };

    function setSqlPreset(name) {
      if (SQL_PRESETS[name]) {
        document.getElementById('sql-input').value = SQL_PRESETS[name];
        runSqlQuery();
      }
    }

    async function runSqlQuery() {
      const sql = document.getElementById('sql-input').value;
      const meta = document.getElementById('sql-meta-bar');
      const container = document.getElementById('sql-results-container');
      const thead = document.getElementById('sql-results-head');
      const tbody = document.getElementById('sql-results-body');

      meta.style.display = 'block';
      meta.textContent = 'Executing query in DuckDB...';

      try {
        const res = await fetch('/api/query', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ query: sql, limit: 500 })
        });
        const data = await res.json();
        if (data.error) {
          meta.innerHTML = `<span style="color:var(--rose);">[!] Error: ${escapeHtml(data.error)}</span>`;
          container.style.display = 'none';
          return;
        }

        meta.innerHTML = `<span style="color:var(--emerald);">✔ Query executed successfully:</span> ${data.row_count} rows in ${data.duration_ms}ms`;
        container.style.display = 'block';

        if (!data.columns || data.columns.length === 0) {
          thead.innerHTML = '';
          tbody.innerHTML = `<tr><td style="padding:20px;color:var(--text-muted);">${data.message || 'No output.'}</td></tr>`;
          return;
        }

        thead.innerHTML = '<tr>' + data.columns.map(c => `<th>${escapeHtml(c)}</th>`).join('') + '</tr>';
        tbody.innerHTML = data.rows.map(row => {
          return '<tr>' + row.map(val => `<td style="font-family:var(--mono);font-size:12px;">${escapeHtml(String(val !== null ? val : 'NULL'))}</td>`).join('') + '</tr>';
        }).join('');
      } catch (err) {
        meta.innerHTML = `<span style="color:var(--rose);">Network/API Error: ${err.message}</span>`;
      }
    }

    // Live Target Prober
    async function runLiveProbe() {
      const target = document.getElementById('probe-target-input').value.trim();
      if (!target) {
        alert('Please enter a target host or IP.');
        return;
      }
      const port = parseInt(document.getElementById('probe-port-input').value) || 11434;
      const apiKey = document.getElementById('probe-key-input').value.trim();
      const runSpeed = document.getElementById('probe-speed-check').checked;
      const useHttps = document.getElementById('probe-https-check').checked;

      const resultBox = document.getElementById('probe-result-box');
      resultBox.style.display = 'block';
      resultBox.innerHTML = `
        <div style="background:var(--card-bg);border:1px solid var(--cyan);border-radius:8px;padding:20px;text-align:center;">
          <p style="color:var(--cyan);font-weight:600;margin-bottom:6px;">Probing target ${escapeHtml(target)}:${port}...</p>
          <p style="font-size:12px;color:var(--text-muted);">Testing /api/tags, /v1/models, and chat authorization endpoints</p>
        </div>
      `;

      try {
        const res = await fetch('/api/probe', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ target, port, use_https: useHttps, api_key: apiKey, run_speed: runSpeed })
        });
        const data = await res.json();
        if (!data.success) {
          resultBox.innerHTML = `
            <div style="background:var(--card-bg);border:1px solid var(--rose);border-radius:8px;padding:20px;">
              <h4 style="color:var(--rose);margin-bottom:8px;">❌ Probe Failed</h4>
              <p style="font-size:13px;color:var(--text-muted);">${escapeHtml(data.error || 'Unknown error occurred')}</p>
            </div>
          `;
          return;
        }

        const rep = data.report;
        resultBox.innerHTML = `
          <div style="background:var(--card-bg);border:1px solid var(--emerald);border-radius:8px;padding:20px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
              <h4 style="color:var(--emerald);">✔ Probe Completed & Saved to DuckDB</h4>
              <button class="btn" style="padding:4px 8px;font-size:11px;" onclick="inspectTarget('${encodeURIComponent(rep.base_url)}')">Inspect Full Report</button>
            </div>
            <p><strong>Target:</strong> <span style="font-family:var(--mono);color:#38bdf8;">${rep.base_url}</span></p>
            <p><strong>Status:</strong> ${escapeHtml(rep.tags_api && rep.tags_api.success ? 'Tags OK' : 'Failed')} | Chat: ${escapeHtml(rep.chat_auth ? rep.chat_auth.summary_status : 'N/A')}</p>
            <p><strong>Discovered Models:</strong> ${rep.tags_api && rep.tags_api.models ? rep.tags_api.models.length : 0} models found</p>
          </div>
        `;
        fetchStats();
      } catch (err) {
        resultBox.innerHTML = `
          <div style="background:var(--card-bg);border:1px solid var(--rose);border-radius:8px;padding:20px;">
            <p style="color:var(--rose);">Error during probe request: ${err.message}</p>
          </div>
        `;
      }
    }

    function exportCurrent(fmt) {
      if (!fmt) return;
      const q = document.getElementById('target-search').value;
      window.location.href = `/api/export?format=${fmt}&q=${encodeURIComponent(q)}&status=${encodeURIComponent(currentStatus)}`;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    // Keyboard shortcut for SQL run
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (currentTab === 'sql') {
          e.preventDefault();
          runSqlQuery();
        }
      }
    });

    // Initialize
    fetchStats();
    fetchTargets();
  </script>
</body>
</html>
"""


# ============================================================================
# Server Initialization & CLI
# ============================================================================

def run_server(
    host: str = "0.0.0.0",
    port: int = 2000,
    db_path: str = "ollama_targets.duckdb",
) -> int:
    """Launch multi-threaded DuckDB Web Dashboard HTTP server."""
    if not os.path.exists(db_path):
        print(f"[*] Warning: Database file '{db_path}' does not exist yet. It will be initialized.")

    try:
        engine = DuckDBEngine(db_path)
    except Exception as e:
        sys.stderr.write(f"[!] Error opening DuckDB database '{db_path}': {e}\n")
        return 1

    class InjectedDashboardHandler(DashboardHandler):
        pass

    InjectedDashboardHandler.engine = engine

    # Ensure port reuse
    ThreadingHTTPServer.allow_reuse_address = True
    try:
        server = ThreadingHTTPServer((host, port), InjectedDashboardHandler)
    except OSError as e:
        sys.stderr.write(f"[!] Error: Unable to bind to {host}:{port}: {e}\n")
        if "Address already in use" in str(e):
            sys.stderr.write(f"    Check for existing processes running on port {port} (e.g. `lsof -i :{port}`).\n")
        return 1

    display_host = "localhost" if host == "0.0.0.0" else host
    print(f"\n==================================================================")
    print(f"  🌐 Ollama DuckDB Web Dashboard is ONLINE")
    print(f"     URL:           http://{display_host}:{port}")
    print(f"     Database:      {os.path.abspath(db_path)}")
    print(f"     API Endpoints: http://{display_host}:{port}/api/stats")
    print(f"                    http://{display_host}:{port}/api/targets")
    print(f"                    http://{display_host}:{port}/api/models")
    print(f"     Press Ctrl+C to stop the dashboard server.")
    print(f"==================================================================\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping dashboard server...")
    finally:
        server.server_close()
        engine.conn.close()
        print("[*] Dashboard server stopped.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="web_dashboard",
        description="Web dashboard for reading, filtering, and searching in DuckDB database on port 2000.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host address to bind the web dashboard server to (default: 0.0.0.0).",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=2000,
        help="Port number to run the web dashboard server on (default: 2000).",
    )
    parser.add_argument(
        "-db", "--db",
        type=str,
        default="ollama_targets.duckdb",
        dest="db_path",
        help="Path to DuckDB database file (default: ollama_targets.duckdb).",
    )

    args = parser.parse_args()
    return run_server(host=args.host, port=args.port, db_path=args.db_path)


if __name__ == "__main__":
    sys.exit(main())
