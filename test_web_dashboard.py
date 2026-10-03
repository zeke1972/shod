#!/usr/bin/env python3
"""
Unit and integration tests for web_dashboard.py
"""

import json
import os
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import duckdb
from web_dashboard import (
    DashboardHandler,
    DuckDBEngine,
    run_server,
)
from ollama_cli import init_duckdb, save_target_to_duckdb


def create_mock_report(
    host="192.168.1.50",
    port=11434,
    authorized=True,
    models=None,
    speed=12.5,
    latency=45.2,
):
    if models is None:
        models = [
            {
                "name": "llama3:8b",
                "model": "llama3:8b",
                "size": 4920737792,
                "details": {
                    "parameter_size": "8.0B",
                    "quantization_level": "Q4_0",
                    "format": "gguf",
                    "family": "llama",
                },
            }
        ]

    return {
        "target": f"{host}:{port}",
        "host": host,
        "port": port,
        "base_url": f"http://{host}:{port}",
        "use_https": False,
        "scanned_at": "2026-09-17T20:00:00.000000Z",
        "tags_api": {
            "success": True,
            "models": models,
            "error": None,
            "status_code": 200,
            "latency_ms": latency,
            "version": "0.1.32",
            "is_unauthorized": not authorized,
        },
        "openai_api": {
            "success": True,
            "models": [m["name"] for m in models],
            "error": None,
            "status_code": 200,
            "latency_ms": latency,
        },
        "chat_auth": {
            "tested": True,
            "is_authorized": authorized,
            "is_unauthorized": not authorized,
            "summary_status": "OPEN" if authorized else "PROTECTED",
            "model_tested": models[0]["name"] if models else None,
            "endpoints": {
                "/api/chat": {"authorized": authorized, "status_code": 200 if authorized else 401, "error": None if authorized else "Unauthorized"},
                "/v1/chat/completions": {"authorized": authorized, "status_code": 200 if authorized else 401, "error": None if authorized else "Unauthorized"},
            },
        },
        "chat_speed": {
            "tested": True,
            "success": True,
            "tokens_per_second": speed,
            "duration_s": 0.8,
            "model": models[0]["name"] if models else None,
        } if speed else {"tested": False, "success": False},
        "overall_success": True,
    }


class TestDuckDBEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_file = os.path.join(self.temp_dir.name, "test_dashboard.duckdb")
        self.engine = DuckDBEngine(self.db_file)

    def tearDown(self):
        self.engine.conn.close()
        self.temp_dir.cleanup()

    def test_empty_stats(self):
        stats = self.engine.get_stats()
        self.assertEqual(stats["total_targets"], 0)
        self.assertEqual(stats["authorized"], 0)
        self.assertEqual(stats["total_models"], 0)

    def test_stats_populated(self):
        rep1 = create_mock_report(host="10.0.0.1", authorized=True, speed=25.0)
        rep2 = create_mock_report(host="10.0.0.2", authorized=False, speed=None)
        save_target_to_duckdb(self.engine.conn, rep1)
        save_target_to_duckdb(self.engine.conn, rep2)

        stats = self.engine.get_stats()
        self.assertEqual(stats["total_targets"], 2)
        self.assertEqual(stats["authorized"], 1)
        self.assertEqual(stats["unauthorized"], 1)
        self.assertEqual(stats["total_models"], 2)
        self.assertGreater(stats["max_speed_tok_s"], 0)

    def test_get_targets_filtering(self):
        rep1 = create_mock_report(host="10.0.0.1", port=11434, authorized=True, models=[{"name": "deepseek-r1:7b", "size": 100, "details": {}}])
        rep2 = create_mock_report(host="10.0.0.2", port=11435, authorized=False, models=[{"name": "mistral:latest", "size": 100, "details": {}}])
        save_target_to_duckdb(self.engine.conn, rep1)
        save_target_to_duckdb(self.engine.conn, rep2)

        # Search by query
        res = self.engine.get_targets(q="deepseek")
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["targets"][0]["host"], "10.0.0.1")

        # Filter by status: open
        res_open = self.engine.get_targets(status="open")
        self.assertEqual(res_open["total"], 1)
        self.assertEqual(res_open["targets"][0]["host"], "10.0.0.1")

        # Filter by status: unauthorized
        res_unauth = self.engine.get_targets(status="unauthorized")
        self.assertEqual(res_unauth["total"], 1)
        self.assertEqual(res_unauth["targets"][0]["host"], "10.0.0.2")

        # Filter by port
        res_port = self.engine.get_targets(port=11435)
        self.assertEqual(res_port["total"], 1)
        self.assertEqual(res_port["targets"][0]["host"], "10.0.0.2")

        # Filter by model
        res_model = self.engine.get_targets(model="mistral")
        self.assertEqual(res_model["total"], 1)
        self.assertEqual(res_model["targets"][0]["host"], "10.0.0.2")

    def test_get_target_detail(self):
        rep = create_mock_report(host="10.0.0.5", authorized=True)
        save_target_to_duckdb(self.engine.conn, rep)

        detail = self.engine.get_target_detail("10.0.0.5")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["host"], "10.0.0.5")
        self.assertTrue(detail["is_authorized"])
        self.assertEqual(len(detail["models"]), 1)
        self.assertEqual(detail["models"][0]["name"], "llama3:8b")

        missing = self.engine.get_target_detail("non_existent_ip")
        self.assertIsNone(missing)

    def test_get_models_grouped_and_ungrouped(self):
        models = [
            {"name": "qwen2.5:7b", "size": 4000000000, "details": {"parameter_size": "7B", "quantization_level": "Q4_K_M", "format": "gguf", "family": "qwen2"}},
        ]
        rep1 = create_mock_report(host="10.0.0.1", authorized=True, models=models)
        rep2 = create_mock_report(host="10.0.0.2", authorized=False, models=models)
        save_target_to_duckdb(self.engine.conn, rep1)
        save_target_to_duckdb(self.engine.conn, rep2)

        # Grouped
        res_grouped = self.engine.get_models(grouped=True)
        self.assertEqual(res_grouped["total"], 1)
        first = res_grouped["models"][0]
        self.assertEqual(first["name"], "qwen2.5:7b")
        self.assertEqual(first["host_count"], 2)
        self.assertEqual(first["open_hosts"], 1)

        # Ungrouped
        res_ungrouped = self.engine.get_models(grouped=False)
        self.assertEqual(res_ungrouped["total"], 2)

    def test_execute_sql(self):
        rep = create_mock_report(host="10.0.0.1")
        save_target_to_duckdb(self.engine.conn, rep)

        # Valid query
        res = self.engine.execute_sql("SELECT count(*) as cnt FROM targets")
        self.assertNotIn("error", res)
        self.assertEqual(res["columns"], ["cnt"])
        self.assertEqual(res["rows"][0][0], 1)

        # Empty query
        res_empty = self.engine.execute_sql("   ")
        self.assertIn("error", res_empty)

        # Disallowed query
        res_disallowed = self.engine.execute_sql("PRAGMA table_info('targets')")
        self.assertIn("error", res_disallowed)
        self.assertIn("restricted", res_disallowed["error"])

        # Syntax error
        res_syntax = self.engine.execute_sql("SELECT * FROM invalid_table_name_xyz")
        self.assertIn("error", res_syntax)


class TestDashboardServerHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_file = os.path.join(cls.temp_dir.name, "server_test.duckdb")
        cls.engine = DuckDBEngine(cls.db_file)

        # Seed test data
        rep1 = create_mock_report(host="192.168.1.10", port=11434, authorized=True, speed=35.0)
        rep2 = create_mock_report(host="192.168.1.20", port=11434, authorized=False, speed=None)
        save_target_to_duckdb(cls.engine.conn, rep1)
        save_target_to_duckdb(cls.engine.conn, rep2)

        class CustomHandler(DashboardHandler):
            pass

        CustomHandler.engine = cls.engine

        ThreadingHTTPServer.allow_reuse_address = True
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), CustomHandler)
        cls.port = cls.httpd.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.engine.conn.close()
        cls.temp_dir.cleanup()

    def test_root_html_page(self):
        req = urllib.request.urlopen(f"{self.base_url}/")
        self.assertEqual(req.status, 200)
        self.assertIn("text/html", req.headers.get("Content-Type", ""))
        content = req.read().decode("utf-8")
        self.assertIn("Ollama DuckDB Explorer", content)
        self.assertIn("Targets Explorer", content)
        self.assertIn("DuckDB SQL Studio", content)

    def test_api_stats(self):
        req = urllib.request.urlopen(f"{self.base_url}/api/stats")
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode("utf-8"))
        self.assertEqual(data["total_targets"], 2)
        self.assertEqual(data["authorized"], 1)
        self.assertEqual(data["unauthorized"], 1)

    def test_api_targets(self):
        req = urllib.request.urlopen(f"{self.base_url}/api/targets?status=open")
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode("utf-8"))
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["targets"][0]["host"], "192.168.1.10")

    def test_api_target_detail(self):
        req = urllib.request.urlopen(f"{self.base_url}/api/targets/192.168.1.10")
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode("utf-8"))
        self.assertEqual(data["host"], "192.168.1.10")
        self.assertEqual(len(data["models"]), 1)

    def test_api_target_detail_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base_url}/api/targets/does_not_exist")
        self.assertEqual(ctx.exception.code, 404)

    def test_api_models(self):
        req = urllib.request.urlopen(f"{self.base_url}/api/models?grouped=true")
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode("utf-8"))
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["models"][0]["name"], "llama3:8b")

    def test_api_query_post(self):
        body = json.dumps({"query": "SELECT host, is_authorized FROM targets ORDER BY host"}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/query",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        res = urllib.request.urlopen(req)
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertEqual(data["columns"], ["host", "is_authorized"])
        self.assertEqual(len(data["rows"]), 2)

    def test_api_query_post_restricted(self):
        body = json.dumps({"query": "ATTACH 'secret.db'"}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/query",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)

    def test_api_export_formats(self):
        # Format TXT
        req = urllib.request.urlopen(f"{self.base_url}/api/export?format=txt&status=open")
        self.assertEqual(req.status, 200)
        txt = req.read().decode("utf-8").strip()
        self.assertEqual(txt, "192.168.1.10:11434")

        # Format CSV
        req = urllib.request.urlopen(f"{self.base_url}/api/export?format=csv&status=open")
        self.assertEqual(req.status, 200)
        csv_content = req.read().decode("utf-8")
        self.assertIn("192.168.1.10", csv_content)
        self.assertIn("host,port,base_url", csv_content)

        # Format JSON
        req = urllib.request.urlopen(f"{self.base_url}/api/export?format=json&status=open")
        self.assertEqual(req.status, 200)
        json_data = json.loads(req.read().decode("utf-8"))
        self.assertEqual(len(json_data), 1)
        self.assertEqual(json_data[0]["host"], "192.168.1.10")

    def test_options_cors(self):
        req = urllib.request.Request(f"{self.base_url}/api/stats", method="OPTIONS")
        res = urllib.request.urlopen(req)
        self.assertEqual(res.status, 204)
        self.assertEqual(res.headers.get("Access-Control-Allow-Origin"), "*")


if __name__ == "__main__":
    unittest.main()
