#!/usr/bin/env python3
"""
Ollama Probe & OpenAI REST API Testing CLI

A command-line tool to probe Ollama instances on {ip}:{port} (default: 11434 or OLLAMA_PORT), calling the native
Ollama model listing API (/api/tags), testing the OpenAI-compatible REST API
endpoint (/v1/models), evaluating REST API reply speed (/v1/chat/completions),
and providing an interactive chat with dynamic model selection.

Features:
  - Accepts one or more IPs/hosts on the command line
  - Native Ollama /api/tags inspection (size, digest, quantization, parameters)
  - OpenAI /v1/models REST API specification verification and latency test
  - OpenAI REST API chat speed evaluation (latency, tokens/sec, TTFT)
  - Interactive chat session with model selection and live streaming
  - Parity comparison between Ollama and OpenAI model registries
  - Support for reading targets from file or stdin (for Shodan / network sweeps)
  - JSON output mode for scripting and pipeline integration
  - Colorful Rich tables or clean plain text fallback
"""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    import readline  # Enables arrow keys and line editing in input()
    HAS_READLINE = True
except ImportError:
    readline = None  # type: ignore
    HAS_READLINE = False

try:
    import requests
except ImportError:
    requests = None  # type: ignore

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import duckdb
    HAS_DUCKDB = True
except ImportError:
    duckdb = None  # type: ignore
    HAS_DUCKDB = False



def format_bytes(num_bytes: Optional[int]) -> str:
    """Format bytes into human-readable size (e.g., 10.17 GB, 500 MB)."""
    if num_bytes is None:
        return "N/A"
    n = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024.0:
            if unit == "B":
                return f"{int(n)} B"
            val = f"{n:.2f}".rstrip("0").rstrip(".")
            return f"{val} {unit}"
        n /= 1024.0
    val = f"{n:.2f}".rstrip("0").rstrip(".")
    return f"{val} PB"


def format_time_ago(iso_str: Optional[str]) -> str:
    """Format an ISO timestamp to relative time (e.g. '3h ago', '2d ago')."""
    if not iso_str:
        return "N/A"
    try:
        clean_str = re.sub(r'([+-]\d{2}):(\d{2})$', r'\1\2', str(iso_str))
        dt = datetime.datetime.fromisoformat(clean_str)
        now = datetime.datetime.now(dt.tzinfo) if dt.tzinfo else datetime.datetime.utcnow()
        diff = now - dt
        seconds = int(diff.total_seconds())
        if seconds < 0:
            return "just now"
        if seconds < 60:
            return f"{seconds}s ago"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        if days < 30:
            return f"{days}d ago"
        months = days // 30
        if months < 12:
            return f"{months}mo ago"
        years = months // 12
        return f"{years}y ago"
    except Exception:
        return str(iso_str).split("T")[0]


def clean_error_message(err: Optional[str]) -> str:
    """Extract clean, human-readable error descriptions from raw exception strings."""
    if not err:
        return "Unknown error"
    err_str = str(err)
    if "Connection refused" in err_str:
        return "Connection refused (port closed or Ollama not running)"
    if "timed out" in err_str.lower():
        return "Connection timed out"
    if "Name or service not known" in err_str or "getaddrinfo failed" in err_str:
        return "DNS resolution failed (host not found)"
    if "No route to host" in err_str:
        return "No route to host (network unreachable)"
    match = re.search(r"Failed to establish a new connection:\s*\[Errno\s*\d+\]\s*([^'\"]+)", err_str)
    if match:
        return match.group(1).strip()
    return err_str


def parse_auth_error(status_code: int, body: Any) -> str:
    """Extract informative explanation when an endpoint returns 401 Unauthorized or 403 Forbidden."""
    default_msg = "Authentication credentials missing or invalid" if status_code == 401 else "Access forbidden"
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msg = err.get("message")
            if msg:
                return str(msg)
        elif isinstance(err, str):
            return err
        detail = body.get("detail") or body.get("message")
        if detail:
            return str(detail)
    if isinstance(body, str) and body.strip():
        first_line = body.strip().split("\n")[0].strip()
        if 0 < len(first_line) < 100 and not first_line.startswith("<"):
            return first_line
    return default_msg


def format_duration(seconds: float) -> str:
    """Format duration in seconds to a human-readable mm:ss or hh:mm:ss string."""
    if seconds < 0 or seconds != seconds:
        return "00:00"
    total_sec = int(round(seconds))
    hours = total_sec // 3600
    minutes = (total_sec % 3600) // 60
    secs = total_sec % 60
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


class SlidingETA:
    """
    Calculates sliding window ETA (estimated time of arrival) and average throughput
    based on the most recent N processed items.
    """

    def __init__(self, total_items: int, window_size: int = 10):
        self.total_items = max(0, total_items)
        self.window_size = max(1, window_size)
        self.start_time = time.perf_counter()
        self.durations: List[float] = []
        self.processed_count = 0

    def record_item(self, duration: float) -> None:
        """Record the processing duration for a completed item."""
        self.processed_count += 1
        self.durations.append(max(0.0, float(duration)))
        if len(self.durations) > self.window_size:
            self.durations.pop(0)

    @property
    def remaining(self) -> int:
        """Number of remaining items to process."""
        return max(0, self.total_items - self.processed_count)

    @property
    def elapsed_seconds(self) -> float:
        """Total elapsed seconds since start."""
        return max(0.0, time.perf_counter() - self.start_time)

    @property
    def sliding_rate(self) -> float:
        """Average seconds per item over the recent sliding window."""
        if not self.durations:
            return 0.0
        return sum(self.durations) / len(self.durations)

    @property
    def eta_seconds(self) -> float:
        """Estimated seconds remaining based on sliding window average rate."""
        if not self.durations or self.remaining <= 0:
            return 0.0
        return self.sliding_rate * self.remaining

    def format_eta(self) -> str:
        """Return formatted ETA string (e.g. '00:15' or '01:23:45')."""
        if self.processed_count == 0 or not self.durations:
            return "calculating..."
        if self.remaining <= 0:
            return "00:00"
        return format_duration(self.eta_seconds)

    def format_elapsed(self) -> str:
        """Return formatted elapsed time string (e.g. '00:08')."""
        return format_duration(self.elapsed_seconds)


def format_target_status_brief(report: Dict[str, Any]) -> str:
    """Return a concise 1-line status summary for a probed target."""
    if not report:
        return "UNKNOWN"

    err = report.get("error")
    tags_res = report.get("tags_api") or {}
    openai_res = report.get("openai_api") or {}
    chat_res = report.get("chat_auth") or {}
    speed_res = report.get("chat_speed") or {}

    # Check for target-level fatal error
    if err and not tags_res.get("success") and not openai_res.get("success"):
        return f"Error: {clean_error_message(err)}"

    # Check unauthorized
    is_unauth = (
        tags_res.get("is_unauthorized")
        or openai_res.get("is_unauthorized")
        or chat_res.get("is_unauthorized")
    )
    if is_unauth:
        status_code = tags_res.get("status_code") or openai_res.get("status_code") or 401
        return f"UNAUTHORIZED (HTTP {status_code})"

    # Check success
    if tags_res.get("success") or openai_res.get("success"):
        models = tags_res.get("models") or openai_res.get("models") or []
        chat_status = chat_res.get("summary_status") or "OPEN"
        parts = [f"OK ({chat_status})", f"{len(models)} model{'s' if len(models) != 1 else ''}"]
        if speed_res and speed_res.get("success") and speed_res.get("tokens_per_second"):
            parts.append(f"{speed_res['tokens_per_second']:.1f} tok/s")
        return ", ".join(parts)

    fail_err = tags_res.get("error") or openai_res.get("error") or "Offline / Unreachable"
    return f"Failed: {clean_error_message(fail_err)}"


def get_default_port() -> int:
    """
    Get default port for Ollama target hosts.
    Checks OLLAMA_PORT or OLLAMA_HOST environment variables, falling back to 11434.
    """
    env_port = os.getenv("OLLAMA_PORT")
    if env_port and env_port.strip().isdigit():
        return int(env_port.strip())
    ollama_host = os.getenv("OLLAMA_HOST", "").strip()
    if ollama_host:
        if ":" in ollama_host:
            try:
                m = re.search(r":(\d+)(?:/|$)", ollama_host)
                if m:
                    return int(m.group(1))
            except Exception:
                pass
        elif ollama_host.isdigit():
            return int(ollama_host)
    return 11434


def parse_target(target: str, default_port: Optional[int] = None, use_https: bool = False) -> Tuple[str, str, int]:
    """
    Parse target string into (base_url, host, port).
    Supports:
      - 192.168.1.1
      - 192.168.1.1:11434
      - 192.168.1.1 11434
      - 192.168.1.1,11434
      - http://192.168.1.1:11434
      - https://192.168.1.1:11434
      - [::1]:11434
      - [::1]
      - hostname:port
      - hostname port
    """
    target = target.strip()
    if not target:
        raise ValueError("Empty target host")

    if default_port is None:
        default_port = get_default_port()

    target = target.rstrip("/")

    # Support space, tab, or comma separation between host and port (e.g. "1.2.3.4 8080" or "1.2.3.4,8080")
    if not (target.startswith("http://") or target.startswith("https://") or target.startswith("[")):
        parts = re.split(r"[\s,]+", target)
        if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            target = f"{parts[0]}:{parts[1]}"

    scheme = "https" if use_https else "http"

    if target.startswith("http://") or target.startswith("https://"):
        parsed = urllib.parse.urlsplit(target)
        scheme = parsed.scheme
        host = parsed.hostname or ""
        port = parsed.port or default_port
    else:
        # Check for IPv6 in brackets [::1]:port or [::1]
        ipv6_match = re.match(r"^\[([a-fA-F0-9:]+)\](?::(\d+))?$", target)
        if ipv6_match:
            host = ipv6_match.group(1)
            port = int(ipv6_match.group(2)) if ipv6_match.group(2) else default_port
        elif ":" in target:
            parts = target.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                host = target
                port = default_port
        else:
            host = target
            port = default_port

    if ":" in host and not host.startswith("["):
        formatted_host = f"[{host}]"
    else:
        formatted_host = host

    base_url = f"{scheme}://{formatted_host}:{port}"
    return base_url, host, port


def is_ip_or_host(token: str) -> bool:
    """Check if token looks like an IP address, target URL, host:port, or IP range."""
    token = token.strip().rstrip("/")
    if not token:
        return False
    if is_ip_range(token):
        return True
    if token.startswith("http://") or token.startswith("https://"):
        return True
    if token.startswith("[") and "]" in token:
        return True
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", token):
        return True
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\s,]+\d+$", token):
        return True
    if token.lower() in ("localhost", "127.0.0.1") or token.lower().startswith("localhost:"):
        return True
    if ":" in token:
        parts = token.rsplit(":", 1)
        if parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            return True
    if re.search(r"[\s,]+", token):
        parts = re.split(r"[\s,]+", token)
        if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            if is_ip_or_host(parts[0]) or re.match(r"^[a-zA-Z0-9.-]+$", parts[0]):
                return True
    return False


MAX_RANGE_HOSTS = 65536


def is_ip_range(token: str) -> bool:
    """
    Check if a string represents an IP address range:
      - CIDR notation: e.g. '192.168.1.0/24', '10.0.0.0/16', '127.0.0.1/30'
      - Hyphen range: e.g. '192.168.1.1-192.168.1.50', '192.168.1.1-50'
      - Wildcard: e.g. '192.168.1.*'
      - Comma-separated combination of ranges.
    """
    token = token.strip()
    if not token:
        return False

    if "," in token:
        parts = [p.strip() for p in token.split(",") if p.strip()]
        return bool(parts) and all(is_ip_range(p) for p in parts)

    # Strip scheme if present
    for scheme in ("http://", "https://"):
        if token.lower().startswith(scheme):
            token = token[len(scheme):]

    # Strip port if present (e.g. :11434)
    if token.startswith("[") and "]" in token:
        closing = token.find("]")
        inside = token[1:closing]
        rest = token[closing + 1:]
        if rest.startswith(":"):
            port_part = rest[1:]
            if port_part.isdigit() and 1 <= int(port_part) <= 65535:
                token = inside
        else:
            token = inside
    elif ":" in token and "/" not in token.split(":")[-1] and "-" not in token.split(":")[-1]:
        parts = token.rsplit(":", 1)
        if parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            token = parts[0]

    # CIDR check
    if "/" in token:
        try:
            ipaddress.ip_network(token, strict=False)
            return True
        except ValueError:
            return False

    # Wildcard check (e.g. 192.168.1.*)
    if token.endswith(".*"):
        prefix = token[:-2]
        try:
            ipaddress.IPv4Address(prefix + ".1")
            return True
        except ValueError:
            return False

    # Dash range check
    if "-" in token:
        parts = token.split("-")
        if len(parts) == 2:
            start_s = parts[0].strip()
            end_s = parts[1].strip()
            try:
                ipaddress.IPv4Address(start_s)
                if "." in end_s:
                    ipaddress.IPv4Address(end_s)
                    return True
                elif end_s.isdigit() and 0 <= int(end_s) <= 255:
                    return True
            except ValueError:
                return False

    return False


def parse_ip_range(token: str) -> List[str]:
    """
    Parse an IP range expression into a list of individual host targets.
    Preserves optional scheme (http://, https://) and port (:11434) if provided.
    Raises ValueError on invalid syntax or if range exceeds safety limit (65536 hosts).
    """
    token = token.strip()
    if not token:
        return []

    # Handle comma-separated list
    if "," in token:
        items = [t.strip() for t in token.split(",") if t.strip()]
        results: List[str] = []
        for item in items:
            results.extend(parse_ip_range(item))
        return results

    scheme = ""
    for s in ("http://", "https://"):
        if token.lower().startswith(s):
            scheme = s
            token = token[len(s):]
            break

    port = None
    if token.startswith("[") and "]" in token:
        closing = token.find("]")
        inside = token[1:closing]
        rest = token[closing + 1:]
        if rest.startswith(":"):
            port_part = rest[1:]
            if port_part.isdigit() and 1 <= int(port_part) <= 65535:
                port = int(port_part)
                token = inside
        else:
            token = inside
    elif ":" in token and "/" not in token.split(":")[-1] and "-" not in token.split(":")[-1]:
        parts = token.rsplit(":", 1)
        if parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            port = int(parts[1])
            token = parts[0]

    def format_item(ip_str: str) -> str:
        if ":" in ip_str and not ip_str.startswith("["):
            ip_str = f"[{ip_str}]"
        res = ip_str
        if port is not None:
            res = f"{res}:{port}"
        if scheme:
            res = f"{scheme}{res}"
        return res

    # 1. CIDR notation
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network '{token}': {e}") from e

        if net.num_addresses > MAX_RANGE_HOSTS:
            raise ValueError(
                f"IP range '{token}' contains {net.num_addresses} addresses, "
                f"which exceeds the safety limit of {MAX_RANGE_HOSTS} hosts (/16). "
                f"Please specify a smaller range."
            )

        if net.num_addresses <= 2:
            ips = [str(ip) for ip in net]
        else:
            ips = [str(ip) for ip in net.hosts()]
        return [format_item(ip) for ip in ips]

    # 2. Wildcard notation (192.168.1.*)
    if token.endswith(".*"):
        prefix = token[:-2]
        try:
            ipaddress.IPv4Address(prefix + ".1")
        except ValueError as e:
            raise ValueError(f"Invalid wildcard IP prefix '{prefix}': {e}") from e
        return [format_item(f"{prefix}.{i}") for i in range(1, 255)]

    # 3. Dash range notation
    if "-" in token:
        parts = token.split("-")
        if len(parts) == 2:
            start_s = parts[0].strip()
            end_s = parts[1].strip()
            try:
                start_ip = ipaddress.IPv4Address(start_s)
            except ValueError as e:
                raise ValueError(f"Invalid starting IP address '{start_s}': {e}") from e

            try:
                if "." in end_s:
                    end_ip = ipaddress.IPv4Address(end_s)
                else:
                    if not (end_s.isdigit() and 0 <= int(end_s) <= 255):
                        raise ValueError(f"Invalid last octet '{end_s}' (must be 0-255)")
                    prefix = start_s.rsplit(".", 1)[0]
                    end_ip = ipaddress.IPv4Address(f"{prefix}.{end_s}")
            except ValueError as e:
                raise ValueError(f"Invalid ending IP address '{end_s}': {e}") from e

            if int(start_ip) > int(end_ip):
                start_ip, end_ip = end_ip, start_ip

            count = int(end_ip) - int(start_ip) + 1
            if count > MAX_RANGE_HOSTS:
                raise ValueError(
                    f"IP range '{start_s}-{end_s}' contains {count} addresses, "
                    f"which exceeds the safety limit of {MAX_RANGE_HOSTS} hosts. "
                    f"Please specify a smaller range."
                )

            ips = [str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
            return [format_item(ip) for ip in ips]

    # 4. Single IP fallback
    try:
        ip = ipaddress.ip_address(token)
        return [format_item(str(ip))]
    except ValueError:
        pass

    raise ValueError(
        f"Unrecognized IP range format '{token}'. "
        f"Specify a CIDR (e.g. 192.168.1.0/24) or range (e.g. 192.168.1.1-192.168.1.50, 192.168.1.1-50)."
    )


def make_request(
    url: str,
    method: str = "GET",
    timeout: float = 5.0,
    headers: Optional[Dict[str, str]] = None,
    json_data: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Any, float, Optional[str]]:
    """
    Make an HTTP request and return (status_code, json_or_text, latency_ms, error_msg).
    Uses requests if available, otherwise urllib.request.
    """
    req_headers = {
        "User-Agent": "ollama-cli-probe/1.0",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)

    start_time = time.perf_counter()

    if requests is not None:
        try:
            if method.upper() == "POST":
                resp = requests.post(url, json=json_data, timeout=timeout, headers=req_headers)
            else:
                resp = requests.get(url, timeout=timeout, headers=req_headers)

            latency_ms = (time.perf_counter() - start_time) * 1000.0
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            return resp.status_code, body, latency_ms, None
        except requests.exceptions.Timeout:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return 0, None, latency_ms, f"Connection timed out after {timeout}s"
        except requests.exceptions.ConnectionError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return 0, None, latency_ms, f"Connection failed: {e.args[0] if e.args else e}"
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return 0, None, latency_ms, f"Request error: {e}"
    else:
        import urllib.error
        import urllib.request

        data_bytes = None
        if json_data is not None:
            data_bytes = json.dumps(json_data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                raw = response.read().decode("utf-8", errors="replace")
                status_code = response.status
                try:
                    body = json.loads(raw)
                except Exception:
                    body = raw
                return status_code, body, latency_ms, None
        except urllib.error.HTTPError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            raw = e.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(raw)
            except Exception:
                body = raw
            return e.code, body, latency_ms, None
        except urllib.error.URLError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return 0, None, latency_ms, f"URL error: {e.reason}"
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return 0, None, latency_ms, f"Request error: {e}"


def check_ollama_tags(base_url: str, timeout: float = 5.0, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Call Ollama native /api/tags endpoint to list models."""
    url = f"{base_url}/api/tags"
    status_code, body, latency_ms, error = make_request(url, timeout=timeout, headers=headers)

    is_unauth = status_code in (401, 403)
    result: Dict[str, Any] = {
        "url": url,
        "status_code": status_code,
        "latency_ms": round(latency_ms, 2),
        "success": False,
        "is_unauthorized": is_unauth,
        "auth_required": is_unauth,
        "models": [],
        "raw": body,
        "error": clean_error_message(error) if error else None,
        "raw_error": error,
    }

    if is_unauth:
        auth_msg = parse_auth_error(status_code, body)
        code_name = "401 Unauthorized" if status_code == 401 else "403 Forbidden"
        result["error"] = f"{code_name}: {auth_msg}"
    elif status_code == 200 and isinstance(body, dict):
        models = body.get("models", [])
        if isinstance(models, list):
            result["success"] = True
            parsed_models = []
            for m in models:
                if isinstance(m, dict):
                    digest = m.get("digest", "")
                    short_id = digest[:12] if digest else "N/A"
                    details = m.get("details", {}) or {}
                    parsed_models.append({
                        "name": m.get("name") or m.get("model") or "unknown",
                        "id": short_id,
                        "digest": digest,
                        "size_bytes": m.get("size"),
                        "size_formatted": format_bytes(m.get("size")),
                        "modified_at": m.get("modified_at"),
                        "modified_ago": format_time_ago(m.get("modified_at")),
                        "format": details.get("format", "gguf"),
                        "family": details.get("family", ""),
                        "parameter_size": details.get("parameter_size", ""),
                        "quantization_level": details.get("quantization_level", ""),
                    })
            result["models"] = parsed_models
        else:
            result["error"] = "Unexpected response structure: 'models' is not a list"
    elif status_code != 200 and not error:
        result["error"] = f"HTTP {status_code}: {body if isinstance(body, str) else json.dumps(body)}"

    return result


def check_openai_models(base_url: str, timeout: float = 5.0, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Test Ollama's OpenAI-compatible REST API at /v1/models."""
    url = f"{base_url}/v1/models"
    status_code, body, latency_ms, error = make_request(url, timeout=timeout, headers=headers)

    is_unauth = status_code in (401, 403)
    result: Dict[str, Any] = {
        "url": url,
        "status_code": status_code,
        "latency_ms": round(latency_ms, 2),
        "success": False,
        "is_openai_compatible": False,
        "is_unauthorized": is_unauth,
        "auth_required": is_unauth,
        "models": [],
        "raw": body,
        "error": clean_error_message(error) if error else None,
        "raw_error": error,
    }

    if is_unauth:
        auth_msg = parse_auth_error(status_code, body)
        code_name = "401 Unauthorized" if status_code == 401 else "403 Forbidden"
        result["error"] = f"{code_name}: {auth_msg}"
    elif status_code == 200 and isinstance(body, dict):
        is_list_obj = body.get("object") == "list"
        data = body.get("data", [])

        if is_list_obj and isinstance(data, list):
            result["success"] = True
            result["is_openai_compatible"] = True
            parsed_models = []
            for item in data:
                if isinstance(item, dict):
                    created = item.get("created")
                    created_str = "N/A"
                    if created:
                        try:
                            created_dt = datetime.datetime.fromtimestamp(created, tz=datetime.timezone.utc)
                            created_str = created_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        except Exception:
                            created_str = str(created)
                    parsed_models.append({
                        "id": item.get("id", "unknown"),
                        "object": item.get("object", "model"),
                        "created": created,
                        "created_str": created_str,
                        "owned_by": item.get("owned_by", ""),
                    })
            result["models"] = parsed_models
        else:
            result["error"] = f"JSON returned, but missing standard OpenAI keys (object='list', data=[...])."
    elif status_code != 200 and not error:
        result["error"] = f"HTTP {status_code}: {body if isinstance(body, str) else json.dumps(body)}"

    return result


def check_single_chat_endpoint(
    url: str,
    payload: Dict[str, Any],
    timeout: float = 5.0,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Test a single chat endpoint (e.g. /api/chat or /v1/chat/completions) for authorization."""
    status_code, body, latency_ms, error = make_request(
        url,
        method="POST",
        timeout=timeout,
        headers=headers,
        json_data=payload,
    )

    has_auth_header = bool(headers and any(k.lower() == "authorization" for k in headers))
    is_unauth = status_code in (401, 403)

    res: Dict[str, Any] = {
        "url": url,
        "status_code": status_code,
        "latency_ms": round(latency_ms, 2),
        "is_authorized": False,
        "is_unauthorized": is_unauth,
        "auth_status": "UNKNOWN",
        "message": "",
        "raw": body,
        "error": clean_error_message(error) if error else None,
    }

    if is_unauth:
        res["auth_status"] = "UNAUTHORIZED" if status_code == 401 else "FORBIDDEN"
        auth_msg = parse_auth_error(status_code, body)
        code_name = "401 Unauthorized" if status_code == 401 else "403 Forbidden"
        res["message"] = f"{code_name}: {auth_msg}"
        res["error"] = res["message"]
    elif status_code == 200:
        res["is_authorized"] = True
        res["auth_status"] = "AUTHENTICATED" if has_auth_header else "OPEN"
        res["message"] = "Authorized (authenticated with credentials)" if has_auth_header else "Open (unauthenticated access permitted)"
    elif status_code == 404:
        # A 404 with "model not found" confirms the server/proxy allowed the request through to Ollama
        body_str = json.dumps(body) if isinstance(body, dict) else str(body or "")
        if "model" in body_str.lower() and ("not found" in body_str.lower() or "does not exist" in body_str.lower()):
            res["is_authorized"] = True
            res["auth_status"] = "AUTHENTICATED" if has_auth_header else "OPEN"
            res["message"] = "Authorized (authenticated with credentials)" if has_auth_header else "Open (unauthenticated access permitted)"
        else:
            res["auth_status"] = "NOT_FOUND"
            res["message"] = f"Endpoint not found (HTTP 404): {body_str[:100]}"
            res["error"] = res["message"]
    elif status_code == 400:
        # Some proxies/gateways validate model name before Ollama
        body_str = json.dumps(body) if isinstance(body, dict) else str(body or "")
        if "model" in body_str.lower():
            res["is_authorized"] = True
            res["auth_status"] = "AUTHENTICATED" if has_auth_header else "OPEN"
            res["message"] = "Authorized (gateway reached)" if has_auth_header else "Open (gateway reached)"
        else:
            res["auth_status"] = "BAD_REQUEST"
            res["message"] = f"HTTP 400: {body_str[:100]}"
            res["error"] = res["message"]
    elif status_code == 0:
        res["auth_status"] = "ERROR"
        res["message"] = clean_error_message(error)
        res["error"] = res["message"]
    else:
        res["auth_status"] = f"HTTP_{status_code}"
        res["message"] = f"HTTP {status_code}: {str(body)[:100]}"
        res["error"] = res["message"]

    return res


def check_chat_authorization(
    base_url: str,
    model: Optional[str] = None,
    available_models: Optional[List[Dict[str, Any]]] = None,
    timeout: float = 5.0,
    headers: Optional[Dict[str, str]] = None,
    fast_probe: bool = True,
) -> Dict[str, Any]:
    """
    Check if Ollama chat endpoints are authorized, open, or partially authorized.
    Probes both native Ollama chat (/api/chat) and OpenAI REST chat (/v1/chat/completions).

    - If a specific model is requested (via model=...), tests that exact model directly.
    - If no model is specified, sends an auth_probe to verify front-door gateway auth,
      and if open, verifies actual local and cloud models on the host to prevent false
      positives (e.g. hosts where cloud proxy models return 401 Unauthorized while
      local models are open).
    """
    # Case 1: Specific model requested by caller
    if model:
        probe_model = model
        native_res = check_single_chat_endpoint(
            f"{base_url}/api/chat",
            {"model": probe_model, "messages": [{"role": "user", "content": "ping"}], "options": {"num_predict": 1}, "stream": False},
            timeout=timeout,
            headers=headers,
        )
        openai_res = check_single_chat_endpoint(
            f"{base_url}/v1/chat/completions",
            {"model": probe_model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1, "stream": False},
            timeout=timeout,
            headers=headers,
        )

        is_unauth = native_res["is_unauthorized"] or openai_res["is_unauthorized"]
        is_auth = native_res["is_authorized"] and openai_res["is_authorized"]

        if native_res["auth_status"] == "UNAUTHORIZED" or openai_res["auth_status"] == "UNAUTHORIZED":
            summary = "UNAUTHORIZED"
        elif native_res["auth_status"] == "FORBIDDEN" or openai_res["auth_status"] == "FORBIDDEN":
            summary = "FORBIDDEN"
        elif native_res["auth_status"] == "OPEN" and openai_res["auth_status"] == "OPEN":
            summary = "OPEN"
        elif native_res["auth_status"] == "AUTHENTICATED" and openai_res["auth_status"] == "AUTHENTICATED":
            summary = "AUTHENTICATED"
        elif native_res["is_authorized"] or openai_res["is_authorized"]:
            summary = "PARTIAL"
        elif native_res["auth_status"] == "ERROR" and openai_res["auth_status"] == "ERROR":
            summary = "ERROR"
        else:
            summary = native_res["auth_status"] or openai_res["auth_status"]

        return {
            "url_native": f"{base_url}/api/chat",
            "url_openai": f"{base_url}/v1/chat/completions",
            "probe_model": probe_model,
            "is_specific_model": True,
            "is_authorized": is_auth,
            "is_unauthorized": is_unauth,
            "auth_status": summary,
            "summary_status": summary,
            "native_chat": native_res,
            "openai_chat": openai_res,
        }

    # Case 2: General probe (no specific model specified)
    # Step 2a: Test front-door gateway with dummy model "auth_probe"
    native_gw = check_single_chat_endpoint(
        f"{base_url}/api/chat",
        {"model": "auth_probe", "messages": [{"role": "user", "content": "ping"}], "options": {"num_predict": 1}, "stream": False},
        timeout=timeout,
        headers=headers,
    )
    openai_gw = check_single_chat_endpoint(
        f"{base_url}/v1/chat/completions",
        {"model": "auth_probe", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1, "stream": False},
        timeout=timeout,
        headers=headers,
    )

    # If front-door blocks with 401 or 403, the entire host requires auth
    if native_gw["is_unauthorized"] or openai_gw["is_unauthorized"]:
        summary = "UNAUTHORIZED" if (native_gw["status_code"] == 401 or openai_gw["status_code"] == 401) else "FORBIDDEN"
        return {
            "url_native": f"{base_url}/api/chat",
            "url_openai": f"{base_url}/v1/chat/completions",
            "probe_model": "auth_probe",
            "is_specific_model": False,
            "is_authorized": False,
            "is_unauthorized": True,
            "auth_status": summary,
            "summary_status": summary,
            "native_chat": native_gw,
            "openai_chat": openai_gw,
        }

    # Step 2b: Gateway did not return 401/403. Check actual models to detect mixed / partial authorization
    models = available_models or []
    cloud_models = []
    local_models = []

    for m in models:
        m_name = m.get("name") or m.get("id") or ""
        m_size = m.get("size_bytes") if "size_bytes" in m else m.get("size")
        m_fmt = m.get("format") or m.get("details", {}).get("format") or ""
        is_cloud = (":cloud" in m_name.lower()) or (m_size is not None and m_size < 2000 and not m_fmt)
        if is_cloud:
            cloud_models.append(m_name)
        else:
            local_models.append(m_name)

    cloud_test_res = None
    local_test_res = None

    # Probe cloud model if present (quick check, < 300ms)
    if cloud_models:
        test_cm = cloud_models[0]
        cloud_test_res = check_single_chat_endpoint(
            f"{base_url}/v1/chat/completions",
            {"model": test_cm, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1, "stream": False},
            timeout=min(timeout, 3.0),
            headers=headers,
        )

    # Probe smallest local model if present
    if local_models:
        def get_model_size(name: str) -> int:
            for m in models:
                if (m.get("name") or m.get("id")) == name:
                    sz = m.get("size_bytes") if "size_bytes" in m else m.get("size")
                    return int(sz) if sz else 999999999999
            return 999999999999

        smallest_lm = sorted(local_models, key=get_model_size)[0]
        local_test_res = check_single_chat_endpoint(
            f"{base_url}/v1/chat/completions",
            {"model": smallest_lm, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1, "stream": False},
            timeout=min(timeout, 4.0),
            headers=headers,
        )

    cloud_unauth = bool(cloud_test_res and cloud_test_res["is_unauthorized"])
    cloud_open = bool(cloud_test_res and cloud_test_res["is_authorized"])
    local_open = bool(local_test_res and local_test_res["is_authorized"])
    local_unauth = bool(local_test_res and local_test_res["is_unauthorized"])

    has_auth_header = bool(headers and any(k.lower() == "authorization" for k in headers))

    if cloud_unauth and local_open:
        # MIXED / PARTIAL: Local models are OPEN, but cloud models return 401 Unauthorized!
        summary = "PARTIAL"
        is_auth = True
        is_unauth = False
        sample_lm = local_models[0] if local_models else "local"
        msg = f"Partial: Local models OPEN (e.g. {sample_lm}), but {len(cloud_models)} cloud models 401 UNAUTHORIZED"
        native_gw["auth_status"] = "PARTIAL"
        native_gw["message"] = msg
        openai_gw["auth_status"] = "PARTIAL"
        openai_gw["message"] = msg
    elif (cloud_unauth or local_unauth) and not (cloud_open or local_open):
        # All tested models are unauthorized
        summary = "UNAUTHORIZED"
        is_auth = False
        is_unauth = True
        msg = "All tested models returned 401 Unauthorized"
        native_gw["auth_status"] = "UNAUTHORIZED"
        native_gw["message"] = msg
        openai_gw["auth_status"] = "UNAUTHORIZED"
        openai_gw["message"] = msg
    elif local_open or cloud_open:
        summary = "AUTHENTICATED" if has_auth_header else "OPEN"
        is_auth = True
        is_unauth = False
    else:
        # Fallback to gateway probe results
        summary = native_gw["auth_status"]
        is_auth = native_gw["is_authorized"]
        is_unauth = native_gw["is_unauthorized"]

    return {
        "url_native": f"{base_url}/api/chat",
        "url_openai": f"{base_url}/v1/chat/completions",
        "probe_model": "auth_probe",
        "is_specific_model": False,
        "is_authorized": is_auth,
        "is_unauthorized": is_unauth,
        "auth_status": summary,
        "summary_status": summary,
        "cloud_models_count": len(cloud_models),
        "cloud_models_unauthorized": cloud_unauth,
        "local_models_count": len(local_models),
        "local_models_open": local_open,
        "cloud_sample": cloud_models[0] if cloud_models else None,
        "local_sample": local_models[0] if local_models else None,
        "native_chat": native_gw,
        "openai_chat": openai_gw,
    }


def evaluate_chat_speed(
    base_url: str,
    model: str,
    prompt: str = "Explain in one sentence why the sky is blue.",
    max_tokens: int = 30,
    timeout: float = 30.0,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Send a test chat completion request to /v1/chat/completions to evaluate response speed.
    Measures:
      - Total latency
      - Time To First Token (TTFT)
      - Completion tokens
      - Generation speed (tokens per second)
    """
    url = f"{base_url}/v1/chat/completions"
    req_headers = {
        "User-Agent": "ollama-cli-probe/1.0",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if headers:
        req_headers.update(headers)

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "stream": True,
    }

    result: Dict[str, Any] = {
        "url": url,
        "model": model,
        "prompt": prompt,
        "status_code": 0,
        "success": False,
        "reply": "",
        "completion_tokens": 0,
        "total_latency_ms": 0.0,
        "time_to_first_token_ms": 0.0,
        "generation_time_ms": 0.0,
        "tokens_per_second": 0.0,
        "error": None,
    }

    start_time = time.perf_counter()
    first_token_time: Optional[float] = None
    chunks: List[str] = []

    if requests is not None:
        try:
            resp = requests.post(url, json=payload, headers=req_headers, stream=True, timeout=timeout)
            result["status_code"] = resp.status_code
            if resp.status_code in (401, 403):
                result["is_unauthorized"] = True
                result["auth_required"] = True
                auth_msg = parse_auth_error(resp.status_code, resp.text)
                code_name = "401 Unauthorized" if resp.status_code == 401 else "403 Forbidden"
                result["error"] = f"{code_name}: {auth_msg}"
                return result
            elif resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code}: {resp.text}"
                return result

            for line in resp.iter_lines():
                if not line:
                    continue
                line_str = line.decode("utf-8", errors="replace").strip()
                if line_str.startswith("data: "):
                    data_str = line_str[6:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk_json = json.loads(data_str)
                        choices = chunk_json.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                if first_token_time is None:
                                    first_token_time = time.perf_counter()
                                chunks.append(content)
                    except Exception:
                        pass
            end_time = time.perf_counter()
            result["success"] = True

        except requests.exceptions.Timeout:
            end_time = time.perf_counter()
            result["error"] = f"Chat request timed out after {timeout}s"
            result["total_latency_ms"] = round((end_time - start_time) * 1000.0, 2)
            return result
        except Exception as e:
            end_time = time.perf_counter()
            result["error"] = clean_error_message(str(e))
            result["total_latency_ms"] = round((end_time - start_time) * 1000.0, 2)
            return result
    else:
        # Fallback to stdlib urllib
        import urllib.request
        import urllib.error

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result["status_code"] = response.status
                for line in response:
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if line_str.startswith("data: "):
                        data_str = line_str[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk_json = json.loads(data_str)
                            choices = chunk_json.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    if first_token_time is None:
                                        first_token_time = time.perf_counter()
                                    chunks.append(content)
                        except Exception:
                            pass
            end_time = time.perf_counter()
            result["success"] = True
        except urllib.error.HTTPError as e:
            end_time = time.perf_counter()
            result["status_code"] = e.code
            if e.code in (401, 403):
                result["is_unauthorized"] = True
                result["auth_required"] = True
                raw = e.read().decode("utf-8", errors="replace")
                auth_msg = parse_auth_error(e.code, raw)
                code_name = "401 Unauthorized" if e.code == 401 else "403 Forbidden"
                result["error"] = f"{code_name}: {auth_msg}"
            else:
                result["error"] = f"HTTP {e.code}: {e.reason}"
            result["total_latency_ms"] = round((end_time - start_time) * 1000.0, 2)
            return result
        except Exception as e:
            end_time = time.perf_counter()
            result["error"] = clean_error_message(str(e))
            result["total_latency_ms"] = round((end_time - start_time) * 1000.0, 2)
            return result

    full_reply = "".join(chunks).strip()
    total_sec = end_time - start_time
    ttft_sec = (first_token_time - start_time) if first_token_time else total_sec
    gen_sec = (end_time - first_token_time) if first_token_time else total_sec
    token_count = len(chunks)

    # Estimate tokens/sec based on generation duration
    if gen_sec > 0 and token_count > 0:
        tok_per_sec = token_count / gen_sec
    elif total_sec > 0 and token_count > 0:
        tok_per_sec = token_count / total_sec
    else:
        tok_per_sec = 0.0

    result["reply"] = full_reply
    result["completion_tokens"] = token_count
    result["total_latency_ms"] = round(total_sec * 1000.0, 1)
    result["time_to_first_token_ms"] = round(ttft_sec * 1000.0, 1)
    result["generation_time_ms"] = round(gen_sec * 1000.0, 1)
    result["tokens_per_second"] = round(tok_per_sec, 1)

    return result


def check_version(base_url: str, timeout: float = 3.0, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Quick check of /api/version for version string."""
    url = f"{base_url}/api/version"
    status_code, body, _, _ = make_request(url, timeout=timeout, headers=headers)
    if status_code == 200 and isinstance(body, dict):
        return body.get("version")
    return None


def probe_target(
    target: str,
    default_port: Optional[int] = None,
    timeout: float = 5.0,
    use_https: bool = False,
    api_key: Optional[str] = None,
    run_tags: bool = True,
    run_openai: bool = True,
    run_chat_auth: bool = True,
    run_speed: bool = False,
    selected_model: Optional[str] = None,
    speed_prompt: str = "Explain in one sentence why the sky is blue.",
    speed_tokens: int = 30,
    fast_auth: bool = True,
) -> Dict[str, Any]:
    """Run probe against a single target host."""
    base_url, host, port = parse_target(target, default_port=default_port, use_https=use_https)

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    report: Dict[str, Any] = {
        "target": target,
        "base_url": base_url,
        "host": host,
        "port": port,
        "version": None,
        "tags_api": None,
        "openai_api": None,
        "chat_auth": None,
        "models_match": None,
        "chat_speed": None,
    }

    # Version check
    report["version"] = check_version(base_url, timeout=timeout, headers=headers)

    if run_tags:
        report["tags_api"] = check_ollama_tags(base_url, timeout=timeout, headers=headers)

    if run_openai:
        report["openai_api"] = check_openai_models(base_url, timeout=timeout, headers=headers)

    # Chat authorization check
    if run_chat_auth:
        discovered_models = []
        if report.get("tags_api") and report["tags_api"].get("models"):
            discovered_models = report["tags_api"]["models"]
        elif report.get("openai_api") and report["openai_api"].get("models"):
            discovered_models = report["openai_api"]["models"]

        report["chat_auth"] = check_chat_authorization(
            base_url=base_url,
            model=selected_model,
            available_models=discovered_models,
            timeout=timeout,
            headers=headers,
            fast_probe=fast_auth,
        )

    # Parity check
    if report["tags_api"] and report["openai_api"]:
        tags_success = report["tags_api"].get("success", False)
        openai_success = report["openai_api"].get("success", False)

        if tags_success and openai_success:
            tags_names = set(m["name"] for m in report["tags_api"].get("models", []))
            openai_ids = set(m["id"] for m in report["openai_api"].get("models", []))
            report["models_match"] = (tags_names == openai_ids)
            report["models_diff"] = {
                "in_tags_only": sorted(list(tags_names - openai_ids)),
                "in_openai_only": sorted(list(openai_ids - tags_names)),
            }

    # Speed test
    if run_speed:
        model_to_bench = selected_model
        if not model_to_bench:
            tags_models = report.get("tags_api", {}).get("models", [])
            # Prioritize local non-cloud models to avoid 401 on cloud proxy models
            local_bench = [
                m["name"] for m in tags_models
                if ":cloud" not in m.get("name", "").lower() and (m.get("size_bytes") or m.get("size") or 0) > 2000
            ]
            if local_bench:
                model_to_bench = local_bench[0]
            elif tags_models:
                model_to_bench = tags_models[0]["name"]
            elif report.get("openai_api") and report["openai_api"].get("models"):
                model_to_bench = report["openai_api"]["models"][0]["id"]

        if model_to_bench:
            report["chat_speed"] = evaluate_chat_speed(
                base_url=base_url,
                model=model_to_bench,
                prompt=speed_prompt,
                max_tokens=speed_tokens,
                timeout=max(timeout, 30.0),
                headers=headers,
            )
        else:
            report["chat_speed"] = {
                "success": False,
                "error": "No models available to test chat speed on target.",
            }

    # Record auth_required if any endpoint returned 401 or 403
    report["auth_required"] = any(
        res.get("is_unauthorized")
        for res in [
            report.get("tags_api"),
            report.get("openai_api"),
            report.get("chat_auth"),
            report.get("chat_speed"),
        ]
        if res
    )

    return report


def render_report_rich(reports: List[Dict[str, Any]], verbose: bool = False) -> None:
    """Render probe reports using rich formatting."""
    console = Console()

    for idx, r in enumerate(reports):
        if idx > 0:
            console.print()

        base_url = r["base_url"]
        ver = f" (v{r['version']})" if r.get("version") else ""
        cached_tag = " [dim cyan](cached in DB)[/dim cyan]" if r.get("_cached") else ""
        title = f"[bold cyan]Ollama Host Report:[/bold cyan] [bold white]{base_url}[/bold white]{ver}{cached_tag}"

        tags_res = r.get("tags_api")
        openai_res = r.get("openai_api")
        chat_auth_res = r.get("chat_auth")
        speed_res = r.get("chat_speed")

        summary_lines = []

        # Native /api/tags status
        if tags_res:
            if tags_res["success"]:
                count = len(tags_res["models"])
                ms = tags_res["latency_ms"]
                summary_lines.append(f"[green]✔[/green] Native Ollama API ([bold]/api/tags[/bold]): [green]200 OK[/green] ({count} models, {ms:.1f}ms)")
            elif tags_res.get("is_unauthorized"):
                summary_lines.append(f"[yellow]🔒[/yellow] Native Ollama API ([bold]/api/tags[/bold]): [bold yellow]UNAUTHORIZED (HTTP {tags_res['status_code']})[/bold yellow] - {tags_res.get('error')}")
            else:
                summary_lines.append(f"[red]✖[/red] Native Ollama API ([bold]/api/tags[/bold]): [red]FAILED[/red] - {tags_res.get('error')}")

        # OpenAI /v1/models status
        if openai_res:
            if openai_res["success"]:
                count = len(openai_res["models"])
                ms = openai_res["latency_ms"]
                summary_lines.append(f"[green]✔[/green] OpenAI REST API ([bold]/v1/models[/bold]): [green]200 OK Compatible[/green] ({count} models, {ms:.1f}ms)")
            elif openai_res.get("is_unauthorized"):
                summary_lines.append(f"[yellow]🔒[/yellow] OpenAI REST API ([bold]/v1/models[/bold]): [bold yellow]UNAUTHORIZED (HTTP {openai_res['status_code']})[/bold yellow] - {openai_res.get('error')}")
            else:
                summary_lines.append(f"[red]✖[/red] OpenAI REST API ([bold]/v1/models[/bold]): [red]FAILED[/red] - {openai_res.get('error')}")

        # Chat Authorization status
        if chat_auth_res:
            native_chat = chat_auth_res.get("native_chat", {})
            openai_chat = chat_auth_res.get("openai_chat", {})
            c_unauth = chat_auth_res.get("cloud_models_unauthorized")
            c_cnt = chat_auth_res.get("cloud_models_count", 0)

            # Native Chat status
            n_status = native_chat.get("auth_status")
            n_ms = native_chat.get("latency_ms", 0.0)
            if n_status == "OPEN":
                summary_lines.append(f"[green]✔[/green] Native Chat API ([bold]/api/chat[/bold]): [green]OPEN[/green] (no auth required, {n_ms:.1f}ms)")
            elif n_status == "AUTHENTICATED":
                summary_lines.append(f"[cyan]✔[/cyan] Native Chat API ([bold]/api/chat[/bold]): [cyan]AUTHENTICATED[/cyan] (credentials valid, {n_ms:.1f}ms)")
            elif n_status == "PARTIAL":
                summary_lines.append(f"[yellow]⚠[/yellow] Native Chat API ([bold]/api/chat[/bold]): [bold yellow]PARTIAL[/bold yellow] (Local models [green]OPEN[/green], {c_cnt} cloud models [red]401 UNAUTHORIZED[/red])")
            elif native_chat.get("is_unauthorized"):
                m_info = f" on [bold]{chat_auth_res.get('probe_model')}[/bold]" if chat_auth_res.get("is_specific_model") else ""
                summary_lines.append(f"[yellow]🔒[/yellow] Native Chat API ([bold]/api/chat[/bold]): [bold yellow]UNAUTHORIZED (HTTP {native_chat.get('status_code')})[/bold yellow]{m_info} - {native_chat.get('message')}")
            else:
                summary_lines.append(f"[red]✖[/red] Native Chat API ([bold]/api/chat[/bold]): [red]FAILED[/red] - {native_chat.get('error')}")

            # OpenAI Chat status
            o_status = openai_chat.get("auth_status")
            o_ms = openai_chat.get("latency_ms", 0.0)
            if o_status == "OPEN":
                summary_lines.append(f"[green]✔[/green] OpenAI Chat API ([bold]/v1/chat/completions[/bold]): [green]OPEN[/green] (no auth required, {o_ms:.1f}ms)")
            elif o_status == "AUTHENTICATED":
                summary_lines.append(f"[cyan]✔[/cyan] OpenAI Chat API ([bold]/v1/chat/completions[/bold]): [cyan]AUTHENTICATED[/cyan] (credentials valid, {o_ms:.1f}ms)")
            elif o_status == "PARTIAL":
                summary_lines.append(f"[yellow]⚠[/yellow] OpenAI Chat API ([bold]/v1/chat/completions[/bold]): [bold yellow]PARTIAL[/bold yellow] (Local models [green]OPEN[/green], {c_cnt} cloud models [red]401 UNAUTHORIZED[/red])")
            elif openai_chat.get("is_unauthorized"):
                m_info = f" on [bold]{chat_auth_res.get('probe_model')}[/bold]" if chat_auth_res.get("is_specific_model") else ""
                summary_lines.append(f"[yellow]🔒[/yellow] OpenAI Chat API ([bold]/v1/chat/completions[/bold]): [bold yellow]UNAUTHORIZED (HTTP {openai_chat.get('status_code')})[/bold yellow]{m_info} - {openai_chat.get('message')}")
            else:
                summary_lines.append(f"[red]✖[/red] OpenAI Chat API ([bold]/v1/chat/completions[/bold]): [red]FAILED[/red] - {openai_chat.get('error')}")

            if c_unauth and c_cnt > 0:
                summary_lines.append(f"[yellow]🔑[/yellow] Cloud Models Notice: {c_cnt} cloud models require upstream credentials (e.g. {chat_auth_res.get('cloud_sample')}).")

        if r.get("auth_required"):
            summary_lines.append("[yellow]🔑[/yellow] Authentication Required: Target requires authorization (use [bold]--api-key <key>[/bold] or env var).")

        if r.get("models_match") is True:
            summary_lines.append("[green]✔[/green] Parity Check: Native models and OpenAI models match exactly.")
        elif r.get("models_match") is False:
            summary_lines.append("[yellow]⚠[/yellow] Parity Check: Discrepancy between native and OpenAI model lists.")

        # Speed Evaluation summary
        if speed_res:
            if speed_res.get("success"):
                tok_s = speed_res["tokens_per_second"]
                toks = speed_res["completion_tokens"]
                ttft = speed_res["time_to_first_token_ms"]
                tot = speed_res["total_latency_ms"]
                m_name = speed_res["model"]
                summary_lines.append(
                    f"[green]✔[/green] REST Chat Speed ([bold]/v1/chat/completions[/bold]): [green]{tok_s:.1f} tok/s[/green] "
                    f"({toks} tokens in {tot/1000.0:.2f}s, TTFT: {ttft:.0f}ms) on [bold]{m_name}[/bold]"
                )
            elif speed_res.get("is_unauthorized"):
                summary_lines.append(f"[yellow]🔒[/yellow] REST Chat Speed ([bold]/v1/chat/completions[/bold]): [bold yellow]UNAUTHORIZED[/bold yellow] - {speed_res.get('error')}")
            else:
                summary_lines.append(f"[red]✖[/red] REST Chat Speed ([bold]/v1/chat/completions[/bold]): [red]FAILED[/red] - {speed_res.get('error')}")

        panel_content = "\n".join(summary_lines)
        console.print(Panel(panel_content, title=title, border_style="blue", expand=False))

        # Speed test details
        if speed_res and speed_res.get("success"):
            sp_table = Table(title="OpenAI REST Chat Speed Benchmark", show_header=True, header_style="bold cyan", border_style="dim")
            sp_table.add_column("MODEL", style="bold white")
            sp_table.add_column("SPEED", justify="right", style="bold green")
            sp_table.add_column("TTFT", justify="right", style="yellow")
            sp_table.add_column("TOTAL TIME", justify="right", style="cyan")
            sp_table.add_column("TOKENS", justify="right", style="magenta")
            sp_table.add_column("REPLY PREVIEW", style="dim")

            reply_prev = (speed_res.get("reply") or "").replace("\n", " ")
            if len(reply_prev) > 40:
                reply_prev = reply_prev[:37] + "..."

            sp_table.add_row(
                speed_res["model"],
                f"{speed_res['tokens_per_second']:.1f} tok/s",
                f"{speed_res['time_to_first_token_ms']:.0f} ms",
                f"{speed_res['total_latency_ms']/1000.0:.2f} s",
                str(speed_res["completion_tokens"]),
                reply_prev,
            )
            console.print(sp_table)

        # Native Model Table
        if tags_res and tags_res["success"] and tags_res["models"]:
            table = Table(title="Ollama Models (/api/tags)", show_header=True, header_style="bold magenta", border_style="dim")
            table.add_column("NAME", style="bold white")
            table.add_column("ID", style="cyan")
            table.add_column("SIZE", justify="right", style="green")
            table.add_column("PARAMS", justify="center", style="yellow")
            table.add_column("QUANT", justify="center", style="blue")
            table.add_column("FORMAT", justify="center")
            table.add_column("MODIFIED", style="dim")

            for m in tags_res["models"]:
                table.add_row(
                    m["name"],
                    m["id"],
                    m["size_formatted"],
                    m["parameter_size"] or "—",
                    m["quantization_level"] or "—",
                    m["format"] or "gguf",
                    m["modified_ago"],
                )
            console.print(table)
        elif tags_res and tags_res["success"]:
            console.print("[yellow]No models found in native /api/tags repository.[/yellow]")

        # OpenAI Model Table
        if openai_res and openai_res["success"] and (not tags_res or verbose):
            table_oa = Table(title="OpenAI Endpoint Models (/v1/models)", show_header=True, header_style="bold green", border_style="dim")
            table_oa.add_column("MODEL ID", style="bold white")
            table_oa.add_column("OBJECT", style="cyan")
            table_oa.add_column("OWNED BY", style="yellow")
            table_oa.add_column("CREATED (UTC)", style="dim")

            for m in openai_res["models"]:
                table_oa.add_row(
                    m["id"],
                    m["object"],
                    m["owned_by"],
                    m["created_str"],
                )
            console.print(table_oa)


def render_report_plain(reports: List[Dict[str, Any]], verbose: bool = False) -> None:
    """Render probe reports in plain ASCII."""
    for idx, r in enumerate(reports):
        if idx > 0:
            print("\n" + "=" * 70 + "\n")

        base_url = r["base_url"]
        ver = f" (v{r['version']})" if r.get("version") else ""
        cached_tag = " (cached in DB)" if r.get("_cached") else ""
        print(f"Target: {base_url}{ver}{cached_tag}")
        print("-" * 50)

        tags_res = r.get("tags_api")
        openai_res = r.get("openai_api")
        speed_res = r.get("chat_speed")

        if tags_res:
            if tags_res["success"]:
                print(f"[OK] Native Ollama /api/tags: HTTP 200 ({len(tags_res['models'])} models, {tags_res['latency_ms']:.1f}ms)")
            elif tags_res.get("is_unauthorized"):
                print(f"[UNAUTHORIZED] Native Ollama /api/tags: HTTP {tags_res['status_code']} - {tags_res.get('error')}")
            else:
                print(f"[FAIL] Native Ollama /api/tags: {tags_res.get('error')}")

        if openai_res:
            if openai_res["success"]:
                print(f"[OK] OpenAI REST API /v1/models: HTTP 200 ({len(openai_res['models'])} models, {openai_res['latency_ms']:.1f}ms)")
            elif openai_res.get("is_unauthorized"):
                print(f"[UNAUTHORIZED] OpenAI REST API /v1/models: HTTP {openai_res['status_code']} - {openai_res.get('error')}")
                print("               (Authentication credentials missing or invalid: use --api-key <key>)")
            else:
                print(f"[FAIL] OpenAI REST API /v1/models: {openai_res.get('error')}")

        chat_auth_res = r.get("chat_auth")
        if chat_auth_res:
            native_chat = chat_auth_res.get("native_chat", {})
            openai_chat = chat_auth_res.get("openai_chat", {})
            c_cnt = chat_auth_res.get("cloud_models_count", 0)

            n_status = native_chat.get("auth_status")
            n_ms = native_chat.get("latency_ms", 0.0)
            if n_status in ("OPEN", "AUTHENTICATED"):
                tag = "OPEN" if n_status == "OPEN" else "AUTH"
                print(f"[{tag}] Native Chat API /api/chat: {native_chat.get('message')} ({n_ms:.1f}ms)")
            elif n_status == "PARTIAL":
                print(f"[PARTIAL] Native Chat API /api/chat: Local models OPEN, {c_cnt} cloud models 401 UNAUTHORIZED")
            elif native_chat.get("is_unauthorized"):
                m_info = f" on {chat_auth_res.get('probe_model')}" if chat_auth_res.get("is_specific_model") else ""
                print(f"[UNAUTHORIZED] Native Chat API /api/chat: HTTP {native_chat.get('status_code')}{m_info} - {native_chat.get('message')}")
            else:
                print(f"[FAIL] Native Chat API /api/chat: {native_chat.get('error')}")

            o_status = openai_chat.get("auth_status")
            o_ms = openai_chat.get("latency_ms", 0.0)
            if o_status in ("OPEN", "AUTHENTICATED"):
                tag = "OPEN" if o_status == "OPEN" else "AUTH"
                print(f"[{tag}] OpenAI Chat API /v1/chat/completions: {openai_chat.get('message')} ({o_ms:.1f}ms)")
            elif o_status == "PARTIAL":
                print(f"[PARTIAL] OpenAI Chat API /v1/chat/completions: Local models OPEN, {c_cnt} cloud models 401 UNAUTHORIZED")
            elif openai_chat.get("is_unauthorized"):
                m_info = f" on {chat_auth_res.get('probe_model')}" if chat_auth_res.get("is_specific_model") else ""
                print(f"[UNAUTHORIZED] OpenAI Chat API /v1/chat/completions: HTTP {openai_chat.get('status_code')}{m_info} - {openai_chat.get('message')}")
            else:
                print(f"[FAIL] OpenAI Chat API /v1/chat/completions: {openai_chat.get('error')}")

        if r.get("auth_required"):
            print("[INFO] Authentication is required on this target (pass --api-key <key>).")

        if r.get("models_match") is True:
            print("[OK] Model lists match across both APIs.")
        elif r.get("models_match") is False:
            print("[WARN] Model lists differ between native and OpenAI APIs.")

        if speed_res:
            if speed_res.get("success"):
                tok_s = speed_res["tokens_per_second"]
                toks = speed_res["completion_tokens"]
                tot = speed_res["total_latency_ms"] / 1000.0
                ttft = speed_res["time_to_first_token_ms"]
                m_name = speed_res["model"]
                print(f"[OK] REST Chat Speed /v1/chat/completions: {tok_s:.1f} tok/s ({toks} tokens in {tot:.2f}s, TTFT {ttft:.0f}ms) [{m_name}]")
                print(f"     Reply preview: \"{speed_res.get('reply')}\"")
            elif speed_res.get("is_unauthorized"):
                print(f"[UNAUTHORIZED] REST Chat Speed /v1/chat/completions: HTTP {speed_res.get('status_code', 401)} - {speed_res.get('error')}")
            else:
                print(f"[FAIL] REST Chat Speed /v1/chat/completions: {speed_res.get('error')}")

        # Native models table
        if tags_res and tags_res["success"] and tags_res["models"]:
            print("\nOllama Models (/api/tags):")
            header = f"{'NAME':<45} {'ID':<14} {'SIZE':<10} {'PARAMS':<8} {'MODIFIED'}"
            print(header)
            print("-" * len(header))
            for m in tags_res["models"]:
                print(f"{m['name']:<45} {m['id']:<14} {m['size_formatted']:<10} {(m['parameter_size'] or '—'):<8} {m['modified_ago']}")
        elif tags_res and tags_res["success"]:
            print("\n(No models loaded in /api/tags)")

        if openai_res and openai_res["success"] and (not tags_res or verbose):
            print("\nOpenAI Models (/v1/models):")
            header = f"{'MODEL ID':<45} {'OBJECT':<10} {'OWNED BY':<15} {'CREATED'}"
            print(header)
            print("-" * len(header))
            for m in openai_res["models"]:
                print(f"{m['id']:<45} {m['object']:<10} {m['owned_by']:<15} {m['created_str']}")


def render_report_quiet(reports: List[Dict[str, Any]]) -> None:
    """Render concise one-line status per target."""
    header = f"{'TARGET':<28} {'TAGS':<10} {'OPENAI':<10} {'CHAT':<10} {'MODELS':<8} {'SPEED':<12} {'LATENCY'}"
    print(header)
    print("-" * len(header))
    for r in reports:
        target = r["base_url"]
        tags_res = r.get("tags_api") or {}
        openai_res = r.get("openai_api") or {}

        tags_st = "—" if r.get("tags_api") is None else ("OK" if tags_res.get("success") else ("401 AUTH" if tags_res.get("is_unauthorized") else "ERR"))
        oa_st = "—" if r.get("openai_api") is None else ("OK" if openai_res.get("success") else ("401 AUTH" if openai_res.get("is_unauthorized") else "ERR"))

        chat_res = r.get("chat_auth")
        if chat_res:
            st = chat_res.get("summary_status", "—")
            if st == "OPEN":
                chat_st = "OPEN"
            elif st == "AUTHENTICATED":
                chat_st = "AUTH"
            elif st == "PARTIAL":
                chat_st = "PARTIAL"
            elif st == "UNAUTHORIZED":
                chat_st = "401 AUTH"
            elif st == "FORBIDDEN":
                chat_st = "403 FORBID"
            elif st == "ERROR":
                chat_st = "ERR"
            else:
                chat_st = st[:10]
        else:
            chat_st = "—"

        count = 0
        if tags_res.get("success") and tags_res.get("models"):
            count = len(tags_res["models"])
        elif openai_res.get("success") and openai_res.get("models"):
            count = len(openai_res["models"])

        speed_str = "—"
        if r.get("chat_speed") and r["chat_speed"].get("success"):
            speed_str = f"{r['chat_speed']['tokens_per_second']:.1f} t/s"

        latencies = [
            x["latency_ms"] for x in [
                r.get("tags_api"),
                r.get("openai_api"),
                r.get("chat_auth", {}).get("native_chat") if r.get("chat_auth") else None,
                r.get("chat_auth", {}).get("openai_chat") if r.get("chat_auth") else None,
            ]
            if x and "latency_ms" in x
        ]
        avg_lat = f"{sum(latencies)/len(latencies):.1f}ms" if latencies else "N/A"

        print(f"{target:<28} {tags_st:<10} {oa_st:<10} {chat_st:<10} {count:<8} {speed_str:<12} {avg_lat}")


def pull_ollama_model(
    base_url: str,
    model: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 600.0,
) -> Tuple[bool, str]:
    """
    Pull a model from the Ollama library/registry with live progress updates.
    Returns (success: bool, message: str).
    """
    pull_url = f"{base_url}/api/pull"
    payload = {"name": model, "stream": True}
    data = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    print(f"[*] Pulling '{model}' from {base_url} ...")
    is_tty = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
    last_status = ""

    try:
        if requests:
            req = requests.post(pull_url, json=payload, headers=req_headers, stream=True, timeout=timeout)
            if req.status_code == 404:
                return False, f"Server {base_url} does not support /api/pull (HTTP 404)"
            if req.status_code in (401, 403):
                return False, f"Unauthorized to pull models on {base_url} (HTTP {req.status_code})"
            if req.status_code != 200:
                return False, f"HTTP {req.status_code}: {req.text[:200]}"
            lines_iter = req.iter_lines()
        else:
            import urllib.error
            import urllib.request
            urllib_req = urllib.request.Request(pull_url, data=data, headers=req_headers, method="POST")
            try:
                resp = urllib.request.urlopen(urllib_req, timeout=timeout)
                lines_iter = resp
            except urllib.error.HTTPError as e:
                raw_err = e.read().decode("utf-8", errors="replace")
                if e.code == 404:
                    return False, f"Server {base_url} does not support /api/pull (HTTP 404)"
                if e.code in (401, 403):
                    return False, f"Unauthorized to pull models on {base_url} (HTTP {e.code})"
                return False, f"HTTP {e.code}: {raw_err[:200]}"

        for raw_line in lines_iter:
            if not raw_line:
                continue
            line_str = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else str(raw_line)
            try:
                obj = json.loads(line_str)
            except Exception:
                continue

            if "error" in obj:
                return False, obj["error"]

            status = obj.get("status", "")
            completed = obj.get("completed")
            total = obj.get("total")

            if completed is not None and total and total > 0:
                pct = (completed / total) * 100.0
                comp_str = format_bytes(completed)
                tot_str = format_bytes(total)
                disp = f"\r[*] {status} [{comp_str} / {tot_str}] ({pct:.1f}%)"
                if is_tty:
                    sys.stdout.write(disp)
                    sys.stdout.flush()
                last_status = disp
            elif status and status != last_status:
                if is_tty and last_status.startswith("\r"):
                    sys.stdout.write("\n")
                print(f"[*] {status}")
                last_status = status

            if status == "success":
                if is_tty and last_status.startswith("\r"):
                    sys.stdout.write("\n")
                return True, f"Successfully pulled '{model}'"

        if is_tty and last_status.startswith("\r"):
            sys.stdout.write("\n")
        return True, f"Finished pulling '{model}'"

    except KeyboardInterrupt:
        if is_tty and last_status.startswith("\r"):
            sys.stdout.write("\n")
        return False, f"Pull of '{model}' cancelled by user."
    except Exception as e:
        if is_tty and last_status.startswith("\r"):
            sys.stdout.write("\n")
        return False, f"Error pulling '{model}': {e}"


def interactive_select_model(
    models: List[Dict[str, Any]],
    base_url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Prompt user interactively to pick from available models."""
    if not models and not base_url:
        return None

    if models:
        print("\nAvailable Models on target:")
        for idx, m in enumerate(models, start=1):
            name = m.get("name") or m.get("id", "unknown")
            size = m.get("size_formatted", "")
            params = m.get("parameter_size", "")
            quant = m.get("quantization_level", "")
            m_size = m.get("size_bytes") if "size_bytes" in m else m.get("size")
            m_fmt = m.get("format") or m.get("details", {}).get("format") or ""
            is_cloud = (":cloud" in name.lower()) or (m_size is not None and m_size < 2000 and not m_fmt)

            extra = []
            if size:
                extra.append(size)
            if params:
                extra.append(params)
            if quant:
                extra.append(quant)
            if is_cloud:
                extra.append("cloud proxy [🔒 may require auth]")
            extra_info = f" ({', '.join(extra)})" if extra else ""
            print(f"  [{idx}] {name}{extra_info}")

    while True:
        try:
            if models:
                prompt = f"\nSelect a model [1-{len(models)}] (default 1, 'p' to pull, 'q' to quit): " if base_url else f"\nSelect a model [1-{len(models)}] (default 1, 'q' to quit): "
            else:
                prompt = "\nNo models installed. Enter 'p' or model name to download/pull on remote host ('q' to quit): "
            choice = input(prompt).strip()
            if not choice:
                if models:
                    return models[0].get("name") or models[0].get("id")
                return None
            if choice.lower() in ("q", "quit", "exit"):
                return None

            # Check if user requested pull/download
            if base_url and (
                choice.lower() in ("p", "pull", "/pull", "download", "/download")
                or choice.lower().startswith(("pull ", "/pull ", "download ", "/download ", "p "))
            ):
                parts = choice.split(maxsplit=1)
                pull_target = parts[1].strip() if len(parts) > 1 else ""
                if not pull_target:
                    try:
                        pull_target = input("Enter model name to download/pull on remote host (or press Enter to cancel): ").strip()
                    except (KeyboardInterrupt, EOFError):
                        print()
                        return None
                if not pull_target:
                    print("[*] Pull cancelled.")
                    continue
                pull_ok, pull_msg = pull_ollama_model(base_url, pull_target, headers=headers)
                if pull_ok:
                    print(f"[✔] {pull_msg}")
                    return pull_target
                else:
                    print(f"[✘] {pull_msg}")
                    continue

            if models:
                try:
                    idx = int(choice)
                    if 1 <= idx <= len(models):
                        selected = models[idx - 1]
                        return selected.get("name") or selected.get("id")
                    print(f"Please enter a number between 1 and {len(models)}.")
                    continue
                except ValueError:
                    pass

                # Check if user typed model name directly
                matches = [m for m in models if choice in (m.get("name") or m.get("id", ""))]
                if matches:
                    return matches[0].get("name") or matches[0].get("id")

                # If base_url is available and model was not found in list, offer to pull it
                if base_url:
                    try:
                        do_p = input(f"Model '{choice}' not found in registry. Pull it on {base_url}? [Y/n]: ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        print()
                        return None
                    if do_p in ("", "y", "yes"):
                        pull_ok, pull_msg = pull_ollama_model(base_url, choice, headers=headers)
                        if pull_ok:
                            print(f"[✔] {pull_msg}")
                            return choice
                        else:
                            print(f"[✘] {pull_msg}")
                            continue

                print("Invalid selection. Try again.")
            else:
                if base_url:
                    pull_ok, pull_msg = pull_ollama_model(base_url, choice, headers=headers)
                    if pull_ok:
                        print(f"[✔] {pull_msg}")
                        return choice
                    else:
                        print(f"[✘] {pull_msg}")
                        continue
                print("No models available.")
                return None
        except (KeyboardInterrupt, EOFError):
            print()
            return None


def stream_chat_turn(
    base_url: str,
    model: str,
    messages: List[Dict[str, str]],
    timeout: float = 60.0,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Stream a single turn of chat completion from /v1/chat/completions to stdout.
    Returns (assistant_reply, speed_metrics_dict).
    """
    url = f"{base_url}/v1/chat/completions"
    req_headers = {
        "User-Agent": "ollama-cli-chat/1.0",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if headers:
        req_headers.update(headers)

    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
    }

    start_time = time.perf_counter()
    first_token_time: Optional[float] = None
    chunks: List[str] = []

    if requests is not None:
        resp = requests.post(url, json=payload, headers=req_headers, stream=True, timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"Server returned HTTP {resp.status_code}: {resp.text}")

        for line in resp.iter_lines():
            if not line:
                continue
            line_str = line.decode("utf-8", errors="replace").strip()
            if line_str.startswith("data: "):
                data_str = line_str[6:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk_json = json.loads(data_str)
                    choices = chunk_json.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            if first_token_time is None:
                                first_token_time = time.perf_counter()
                            chunks.append(content)
                            sys.stdout.write(content)
                            sys.stdout.flush()
                except Exception:
                    pass
        end_time = time.perf_counter()
    else:
        import urllib.request
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=req_headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            for line in response:
                line_str = line.decode("utf-8", errors="replace").strip()
                if line_str.startswith("data: "):
                    data_str = line_str[6:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk_json = json.loads(data_str)
                        choices = chunk_json.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                if first_token_time is None:
                                    first_token_time = time.perf_counter()
                                chunks.append(content)
                                sys.stdout.write(content)
                                sys.stdout.flush()
                    except Exception:
                        pass
        end_time = time.perf_counter()

    full_reply = "".join(chunks)
    total_sec = end_time - start_time
    ttft_sec = (first_token_time - start_time) if first_token_time else total_sec
    gen_sec = (end_time - first_token_time) if first_token_time else total_sec
    token_count = len(chunks)

    tok_per_sec = (token_count / gen_sec) if (gen_sec > 0 and token_count > 0) else (token_count / total_sec if total_sec > 0 else 0.0)

    stats = {
        "tokens": token_count,
        "total_sec": total_sec,
        "ttft_ms": ttft_sec * 1000.0,
        "tokens_per_sec": tok_per_sec,
        "tokens_per_second": tok_per_sec,
    }
    return full_reply, stats


# ---------------------------------------------------------------------------
# Interactive Chat Input & Readline Enhancements
# ---------------------------------------------------------------------------

SLASH_COMMANDS = [
    "/model",
    "/run",
    "/pull",
    "/download",
    "/clear",
    "/history",
    "/system",
    "/file",
    "/paste",
    "/multiline",
    "/info",
    "/help",
    "/exit",
    "/quit",
]

EXT_LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".json": "json",
    ".md": "markdown",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sh": "bash",
    ".bash": "bash",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".go": "go",
    ".html": "html",
    ".css": "css",
    ".sql": "sql",
    ".txt": "text",
}

HISTORY_FILE = os.path.expanduser("~/.ollama_cli_history")
_last_sigint_time: float = 0.0


def complete_filepath(text: str) -> List[str]:
    """Generate path completion candidates for the given text prefix."""
    orig_text = text
    expanded = os.path.expanduser(text)
    if not expanded:
        dirname = "."
        prefix = ""
    elif os.path.isdir(expanded) and text.endswith("/"):
        dirname = expanded
        prefix = ""
    else:
        dirname = os.path.dirname(expanded) or "."
        prefix = os.path.basename(expanded)

    try:
        entries = os.listdir(dirname)
    except Exception:
        return []

    matches: List[str] = []
    for entry in sorted(entries):
        if entry.startswith(prefix) and (prefix.startswith(".") or not entry.startswith(".")):
            full_path = os.path.join(dirname, entry)
            if orig_text.startswith("~"):
                user_home = os.path.expanduser("~")
                rel = os.path.relpath(full_path, user_home)
                disp = os.path.join("~", rel)
            elif os.path.isabs(orig_text):
                disp = full_path
            else:
                orig_dir = os.path.dirname(orig_text)
                if orig_dir:
                    disp = os.path.join(orig_dir, entry)
                else:
                    disp = entry
            if os.path.isdir(full_path):
                disp += "/"
            matches.append(disp)
    return matches


def make_chat_completer(slash_commands: List[str], model_names: List[str]):
    """Create a Readline completer function aware of slash commands, model names, and files."""
    def completer(text: str, state: int) -> Optional[str]:
        try:
            line = readline.get_line_buffer() if (HAS_READLINE and readline) else text
        except Exception:
            line = text

        line_stripped = line.lstrip()
        matches: List[str] = []

        if line_stripped.startswith("/model") or line_stripped.startswith("/run"):
            cmd_prefix = "/model" if line_stripped.startswith("/model") else "/run"
            arg = line_stripped[len(cmd_prefix):].lstrip()
            if " " in arg and not arg.endswith(text):
                return None
            matches = [m for m in model_names if m.startswith(text)]

        elif line_stripped.startswith("/pull") or line_stripped.startswith("/download"):
            cmd_prefix = "/pull" if line_stripped.startswith("/pull") else "/download"
            arg = line_stripped[len(cmd_prefix):].lstrip()
            if " " in arg and not arg.endswith(text):
                return None
            common_suggestions = [
                "llama3.2",
                "llama3.2:1b",
                "llama3.2:3b",
                "llama3.1:8b",
                "mistral:7b",
                "phi3:mini",
                "phi3.5",
                "qwen2.5:0.5b",
                "qwen2.5:1.5b",
                "qwen2.5:7b",
                "deepseek-r1:1.5b",
                "deepseek-r1:7b",
                "deepseek-r1:8b",
                "smollm2:135m",
                "smollm2:360m",
                "smollm2:1.7b",
                "gemma2:2b",
                "gemma2:9b",
            ]
            all_candidates = list(dict.fromkeys(model_names + common_suggestions))
            matches = [m for m in all_candidates if m.startswith(text)]

        elif line_stripped.startswith("/file"):
            arg = line_stripped[len("/file"):].lstrip()
            if arg.startswith('"'):
                if arg.count('"') >= 2 and not arg.endswith(text):
                    return None
            else:
                parts = arg.split(maxsplit=1)
                if len(parts) > 1 or (" " in arg and arg.endswith(" ") and not text):
                    return None
            matches = complete_filepath(text)

        elif line_stripped.startswith("/"):
            if " " not in line_stripped:
                matches = [c for c in slash_commands if c.startswith(text)]

        if state < len(matches):
            return matches[state]
        return None

    return completer


def setup_readline(model_names: Optional[List[str]] = None) -> None:
    """Initialize Readline history, keybindings, and context-aware tab completion."""
    if not HAS_READLINE or readline is None:
        return

    # Load persistent history
    try:
        if os.path.exists(HISTORY_FILE):
            readline.read_history_file(HISTORY_FILE)
        readline.set_history_length(1000)
    except Exception:
        pass

    # Configure tab completion
    try:
        readline.set_completer_delims(" \t\n\"'")
        completer = make_chat_completer(SLASH_COMMANDS, model_names or [])
        readline.set_completer(completer)
        if readline.__doc__ and "libedit" in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
    except Exception:
        pass


def save_readline_history() -> None:
    """Save Readline history to ~/.ollama_cli_history."""
    if not HAS_READLINE or readline is None:
        return
    try:
        readline.write_history_file(HISTORY_FILE)
    except Exception:
        pass


def cleanup_readline() -> None:
    """Reset Readline completer to default on session exit."""
    if not HAS_READLINE or readline is None:
        return
    try:
        readline.set_completer(None)
    except Exception:
        pass


def parse_file_command_args(arg: str) -> Tuple[str, str]:
    """Parse file path and optional prompt from /file arguments."""
    arg = arg.strip()
    if not arg:
        return "", ""

    if arg.startswith('"'):
        end_idx = arg.find('"', 1)
        if end_idx != -1:
            filepath = arg[1:end_idx].strip()
            prompt = arg[end_idx + 1:].strip()
            return filepath, prompt
        return arg.strip('"'), ""
    elif arg.startswith("'"):
        end_idx = arg.find("'", 1)
        if end_idx != -1:
            filepath = arg[1:end_idx].strip()
            prompt = arg[end_idx + 1:].strip()
            return filepath, prompt
        return arg.strip("'"), ""
    else:
        parts = arg.split(maxsplit=1)
        filepath = parts[0]
        prompt = parts[1] if len(parts) > 1 else ""
        return filepath, prompt


def load_file_for_chat(arg: str) -> Tuple[bool, str, Optional[str]]:
    """
    Parse argument for /file command, read file content, and format as prompt.
    Returns: (ok: bool, message_or_error: str, resolved_path: Optional[str])
    """
    filepath, prompt = parse_file_command_args(arg)
    if not filepath:
        return False, "Usage: /file <path> [optional prompt instructions]", None

    expanded = os.path.expanduser(filepath)
    if not os.path.exists(expanded):
        return False, f"File not found: {filepath}", None
    if os.path.isdir(expanded):
        return False, f"Path is a directory, not a file: {filepath}", None

    try:
        size = os.path.getsize(expanded)
        max_bytes = 500_000
        with open(expanded, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
            if size > max_bytes:
                content += f"\n\n... [Truncated: file size {format_bytes(size)} exceeds 500 KB limit] ..."
    except Exception as e:
        return False, f"Error reading file {filepath}: {e}", None

    filename = os.path.basename(expanded)
    _, ext = os.path.splitext(filename)
    lang = EXT_LANG_MAP.get(ext.lower(), ext.lstrip(".").lower())

    if prompt:
        formatted = f"{prompt}\n\n```{lang}\n{content}\n```\n(Source: {filepath})"
    else:
        formatted = f"Please examine the following file ({filename}):\n\n```{lang}\n{content}\n```"

    return True, formatted, expanded


def get_user_chat_input(
    prompt_user: Optional[str] = None,
    prompt_cont: Optional[str] = None,
    prompt_paste: Optional[str] = None,
    input_func=input,
) -> Optional[str]:
    """
    Get user input for interactive chat supporting:
      - Line continuation via trailing backslash '\\'
      - Triple-quote block mode (''' or \"\"\")
      - Dedicated /paste or /multiline mode
      - ANSI-safe prompt rendering with \\001 and \\002 markers
      - Double-Ctrl+C or Ctrl+D session termination, single Ctrl+C line cancel
    Returns None if user signaled exit (double Ctrl+C or Ctrl+D), or input string.
    """
    global _last_sigint_time

    is_tty = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
    if prompt_user is None:
        prompt_user = "\n\001\033[1;36m\002[You]\001\033[0m\002: " if is_tty else "\n[You]: "
    if prompt_cont is None:
        prompt_cont = "\001\033[2m\002...  \001\033[0m\002 " if is_tty else "...  "
    if prompt_paste is None:
        prompt_paste = "\001\033[2m\002paste> \001\033[0m\002 " if is_tty else "paste> "

    try:
        first_line = input_func(prompt_user)
        _last_sigint_time = 0.0
    except KeyboardInterrupt:
        now = time.time()
        if (now - _last_sigint_time) < 2.0:
            print("\n[*] Exiting chat session.")
            return None
        _last_sigint_time = now
        print("\n(Press Ctrl+C again, Ctrl+D, or type /exit to quit)")
        return ""
    except EOFError:
        print("\n[*] Exiting chat session.")
        return None

    stripped = first_line.strip()

    # Dedicated /paste or /multiline mode
    if stripped.lower() in ("/paste", "/multiline"):
        print("[*] Entering multi-line / paste mode.")
        print("    Paste or type your text below.")
        print("    Finish with '/send' or '/end' on a new line (or Ctrl+D).")
        print("    Cancel with Ctrl+C or '/cancel'.")
        lines: List[str] = []
        while True:
            try:
                line = input_func(prompt_paste)
            except KeyboardInterrupt:
                print("\n[*] Paste mode cancelled.")
                return ""
            except EOFError:
                break
            s = line.strip().lower()
            if s in ("/send", "/end"):
                break
            if s == "/cancel":
                print("[*] Paste mode cancelled.")
                return ""
            lines.append(line)
        return "\n".join(lines).strip()

    # Triple quotes block mode
    for q in ('"""', "'''"):
        if stripped.startswith(q):
            content_after = stripped[len(q):]
            if q in content_after:
                idx = content_after.find(q)
                return content_after[:idx].strip()

            first_content = first_line[first_line.find(q) + len(q):]
            lines = [first_content] if first_content.strip() else []
            while True:
                try:
                    line = input_func(prompt_cont)
                except KeyboardInterrupt:
                    print("\n[^C Input cancelled]")
                    return ""
                except EOFError:
                    break
                if q in line:
                    idx = line.find(q)
                    part = line[:idx]
                    if part:
                        lines.append(part)
                    break
                lines.append(line)
            return "\n".join(lines).strip()

    # Backslash line continuation
    rstrip_line = first_line.rstrip()
    if rstrip_line.endswith("\\") and not rstrip_line.endswith("\\\\"):
        lines = [rstrip_line[:-1].rstrip()]
        while True:
            try:
                line = input_func(prompt_cont)
            except KeyboardInterrupt:
                print("\n[^C Input cancelled]")
                return ""
            except EOFError:
                break
            s = line.rstrip()
            if s.endswith("\\") and not s.endswith("\\\\"):
                lines.append(s[:-1].rstrip())
            else:
                lines.append(line)
                break
        return "\n".join(lines).strip()

    return first_line


def run_interactive_chat(
    target: str,
    default_port: Optional[int] = None,
    timeout: float = 60.0,
    use_https: bool = False,
    api_key: Optional[str] = None,
    initial_model: Optional[str] = None,
    system_prompt: Optional[str] = None,
) -> int:
    """Run an interactive chat session with live model selection, multi-line input, and streaming replies."""
    base_url, host, port = parse_target(target, default_port=default_port, use_https=use_https)

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    active_model = initial_model

    print(f"[*] Connecting to {base_url} ...")

    # Fetch models from tags or openai
    tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
    models = tags_res.get("models", [])
    openai_res = None
    if not models:
        openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
        models = openai_res.get("models", [])

    if not models:
        unauth = tags_res.get("is_unauthorized") or (openai_res and openai_res.get("is_unauthorized"))
        if unauth:
            unauth_code = tags_res.get("status_code") or (openai_res.get("status_code") if openai_res else 401)
            print(f"\n[🔒] Target requires authentication (HTTP {unauth_code} Unauthorized / Forbidden).")
            try:
                entered_key = input("Enter API key / Bearer token (or press Enter to cancel): ").strip()
                if entered_key:
                    headers["Authorization"] = f"Bearer {entered_key}"
                    tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                    models = tags_res.get("models", [])
                    if not models:
                        openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
                        models = openai_res.get("models", [])
            except (KeyboardInterrupt, EOFError):
                print()
                return 1

    if not models:
        err_msg = tags_res.get('error') or (openai_res.get('error') if openai_res else 'Empty registry')
        print(f"[!] No models found on {base_url}. Reason: {err_msg}")
        is_unauth = tags_res.get("is_unauthorized") or (openai_res and openai_res.get("is_unauthorized"))
        if not is_unauth:
            try:
                suggest_pull = input(f"Would you like to download a model to {base_url} now? [Y/n] (or enter model name): ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                return 1
            if suggest_pull.lower() not in ("n", "no"):
                target_pull = suggest_pull if suggest_pull.lower() not in ("", "y", "yes") else "smollm2:135m"
                pull_ok, pull_msg = pull_ollama_model(base_url, target_pull, headers=headers, timeout=max(timeout, 600.0))
                if pull_ok:
                    tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                    models = tags_res.get("models", [])
                    if not models:
                        openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
                        models = openai_res.get("models", [])
                    active_model = target_pull
                else:
                    print(f"[!] Pull failed: {pull_msg}")
                    return 1
            else:
                return 1
        else:
            return 1

    known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]

    # Select model
    if not active_model:
        active_model = initial_model
    if not active_model:
        active_model = interactive_select_model(models, base_url=base_url, headers=headers)
        if not active_model:
            print("[*] Model selection cancelled. Exiting.")
            return 0
        if active_model not in known_names:
            tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
            updated_models = tags_res.get("models", [])
            if updated_models:
                models = updated_models
                known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]
            if active_model not in known_names:
                known_names.append(active_model)
    else:
        # Verify requested model exists or inform user
        matched = None
        for kn in known_names:
            if kn == active_model or kn == f"{active_model}:latest" or kn.split(":")[0] == active_model:
                matched = kn
                break
        if matched:
            active_model = matched
        else:
            print(f"[!] Warning: '{active_model}' not explicitly listed in available models on {base_url}.")
            try:
                init_pull = input(f"Would you like to download/pull '{active_model}' on {base_url}? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                init_pull = "n"
                print()
            if init_pull in ("", "y", "yes"):
                pull_ok, pull_msg = pull_ollama_model(base_url, active_model, headers=headers, timeout=max(timeout, 600.0))
                if pull_ok:
                    print(f"[✔] {pull_msg}")
                    tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                    updated_models = tags_res.get("models", [])
                    if updated_models:
                        models = updated_models
                        known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]
                else:
                    print(f"[!] Pull failed: {pull_msg}. Proceeding anyway in case server proxies it...")
            else:
                print(f"[*] Proceeding with '{active_model}' as requested.")
        if active_model not in known_names:
            known_names.append(active_model)

    # Welcome banner
    print("\n" + "=" * 65)
    print(f" Connected to Ollama REST API: {base_url}")
    print(f" Active Model: {active_model}")
    print(" Commands: /model | /pull | /clear | /history | /file | /paste | /help | /exit")
    print(" Input:    Trailing \\ or \"\"\" for multiline | /paste | <Tab> completes")
    print("=" * 65 + "\n")

    setup_readline(model_names=known_names)

    messages: List[Dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
        print(f"[System Prompt Active]: {system_prompt}\n")

    try:
        while True:
            user_input = get_user_chat_input()
            if user_input is None:
                break
            user_input = user_input.strip()
            if not user_input:
                continue

            # Command handling
            if user_input.startswith("/"):
                cmd_parts = user_input.split(maxsplit=1)
                cmd = cmd_parts[0].lower()
                arg = cmd_parts[1] if len(cmd_parts) > 1 else ""

                if cmd in ("/exit", "/quit", "/q"):
                    print("[*] Goodbye!")
                    break

                elif cmd in ("/help", "/h"):
                    print("\nChat Commands:")
                    print("  /model           - Interactively select a different model")
                    print("  /model <name>    - Switch directly to specified model (or /run <name>)")
                    print("  /pull <name>     - Download/pull a new model to the remote host")
                    print("  /download <name> - Alias for /pull (download model to remote host)")
                    print("  /clear           - Clear conversation history")
                    print("  /history         - Show current message count & preview")
                    print("  /system <prompt> - Set or update system prompt")
                    print("  /file <path> [p] - Load local file and chat with its content")
                    print("  /paste           - Enter multi-line paste mode (/send to finish)")
                    print("  /info            - Display host, model, and metrics info")
                    print("  /help            - Show this command reference")
                    print("  /exit, /quit     - Exit chat session\n")
                    print("Input Tips:")
                    print("  • Trailing '\\'   : End a line with '\\' to continue on the next line.")
                    print("  • Block mode     : Wrap prompt in \"\"\" or ''' for multi-line blocks.")
                    print("  • Tab complete   : Auto-completes /commands, /model <name>, and /file <path>.")
                    print("  • Persistent hist: Up/Down arrows navigate history; Ctrl+R searches.")
                    print("  • Line cancel    : Press Ctrl+C once to cancel current line without exiting.\n")
                    continue

                elif cmd in ("/pull", "/download"):
                    model_to_pull = arg.strip()
                    if not model_to_pull:
                        try:
                            model_to_pull = input("Enter model name to download/pull (e.g. smollm2:135m, llama3.2, mistral) [or press Enter to cancel]: ").strip()
                        except (KeyboardInterrupt, EOFError):
                            print()
                            continue
                        if not model_to_pull:
                            print("[*] Download cancelled.")
                            continue

                    print(f"[*] Requesting remote host {base_url} to download '{model_to_pull}' ...")
                    pull_ok, pull_msg = pull_ollama_model(base_url, model_to_pull, headers=headers, timeout=max(timeout, 600.0))
                    if pull_ok:
                        print(f"\n[✔] {pull_msg}")
                        tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                        updated_models = tags_res.get("models", [])
                        if not updated_models:
                            openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
                            updated_models = openai_res.get("models", [])
                        if updated_models:
                            models = updated_models
                            known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]
                        if model_to_pull not in known_names:
                            known_names.append(model_to_pull)
                        setup_readline(model_names=known_names)

                        try:
                            switch_ans = input(f"Switch active model to '{model_to_pull}'? [Y/n]: ").strip().lower()
                        except (KeyboardInterrupt, EOFError):
                            switch_ans = "n"
                            print()
                        if switch_ans in ("", "y", "yes"):
                            active_model = model_to_pull
                            print(f"[*] Switched active model to: {active_model}")
                        else:
                            print(f"[*] Active model remains: {active_model}")
                    else:
                        print(f"\n[✘] Pull failed: {pull_msg}")
                    continue

                elif cmd in ("/model", "/run"):
                    if arg:
                        target_model = arg.strip()
                        matched = None
                        for kn in known_names:
                            if kn == target_model or kn == f"{target_model}:latest" or kn.split(":")[0] == target_model:
                                matched = kn
                                break

                        if matched:
                            active_model = matched
                            print(f"[*] Switched model to: {active_model}")
                        else:
                            print(f"[!] Model '{target_model}' is not currently installed on {base_url}.")
                            try:
                                do_pull = input(f"Would you like to download/pull '{target_model}' on {base_url}? [Y/n]: ").strip().lower()
                            except (KeyboardInterrupt, EOFError):
                                do_pull = "n"
                                print()
                            if do_pull in ("", "y", "yes"):
                                pull_ok, pull_msg = pull_ollama_model(base_url, target_model, headers=headers, timeout=max(timeout, 600.0))
                                if pull_ok:
                                    print(f"\n[✔] {pull_msg}")
                                    tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                                    updated_models = tags_res.get("models", [])
                                    if not updated_models:
                                        openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
                                        updated_models = openai_res.get("models", [])
                                    if updated_models:
                                        models = updated_models
                                        known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]
                                    if target_model not in known_names:
                                        known_names.append(target_model)
                                    setup_readline(model_names=known_names)
                                    active_model = target_model
                                    print(f"[*] Switched model to: {active_model}")
                                else:
                                    print(f"\n[✘] Pull failed: {pull_msg}")
                                    print(f"[*] Model kept as: {active_model}")
                            else:
                                active_model = target_model
                                if active_model not in known_names:
                                    known_names.append(active_model)
                                    setup_readline(model_names=known_names)
                                print(f"[*] Proceeding with '{active_model}' as requested.")
                    else:
                        new_model = interactive_select_model(models, base_url=base_url, headers=headers)
                        if new_model:
                            active_model = new_model
                            tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                            updated_models = tags_res.get("models", [])
                            if updated_models:
                                models = updated_models
                                known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]
                            if active_model not in known_names:
                                known_names.append(active_model)
                                setup_readline(model_names=known_names)
                            print(f"[*] Switched model to: {active_model}")
                        else:
                            print(f"[*] Model kept as: {active_model}")
                    continue

                elif cmd == "/file":
                    if not arg:
                        print("[!] Usage: /file <path> [optional prompt instructions]")
                        continue
                    ok, content_or_err, resolved_path = load_file_for_chat(arg)
                    if not ok:
                        print(f"[!] {content_or_err}")
                        continue
                    file_size = os.path.getsize(resolved_path) if resolved_path and os.path.exists(resolved_path) else len(content_or_err)
                    line_count = len(content_or_err.splitlines())
                    print(f"[*] Loaded '{resolved_path}' ({format_bytes(file_size)}, ~{line_count} lines).")
                    user_input = content_or_err
                    # Fall through to send user_input to model

                elif cmd == "/clear":
                    messages.clear()
                    if system_prompt:
                        messages.append({"role": "system", "content": system_prompt})
                    print("[*] Conversation history cleared.")
                    continue

                elif cmd == "/history":
                    print(f"[*] Total messages in context: {len(messages)}")
                    for i, m in enumerate(messages):
                        preview = m['content'].replace('\n', ' ')
                        if len(preview) > 60:
                            preview = preview[:57] + '...'
                        print(f"  [{i+1}] {m['role'].upper()}: {preview}")
                    continue

                elif cmd == "/system":
                    if arg:
                        system_prompt = arg.strip()
                        if messages and messages[0].get("role") == "system":
                            messages[0]["content"] = system_prompt
                        else:
                            messages.insert(0, {"role": "system", "content": system_prompt})
                        print(f"[*] System prompt updated: \"{system_prompt}\"")
                    else:
                        curr = messages[0]["content"] if (messages and messages[0].get("role") == "system") else "(none)"
                        print(f"[*] Current system prompt: {curr}")
                    continue

                elif cmd == "/info":
                    print(f"[*] Target: {base_url}")
                    print(f"[*] Model: {active_model}")
                    print(f"[*] Messages in history: {len(messages)}")
                    continue

                else:
                    print(f"[!] Unknown command '{cmd}'. Type /help for command list.")
                    continue

            # Standard user message (or loaded file prompt)
            messages.append({"role": "user", "content": user_input})
            sys.stdout.write(f"\n\033[1;32m[{active_model}]\033[0m: ")
            sys.stdout.flush()

            try:
                reply, stats = stream_chat_turn(
                    base_url=base_url,
                    model=active_model,
                    messages=messages,
                    timeout=timeout,
                    headers=headers,
                )
                print()  # Newline after stream finishes
                messages.append({"role": "assistant", "content": reply})

                # Print reply speed footer
                tok_s = stats["tokens_per_second"]
                toks = stats["tokens"]
                tot = stats["total_sec"]
                ttft = stats["ttft_ms"]
                print(f"\033[2m[⏱ {tot:.2f}s | {toks} tokens | {tok_s:.1f} tok/s | TTFT: {ttft:.0f}ms]\033[0m")

            except KeyboardInterrupt:
                print("\n[!] Stream interrupted by user.")
            except Exception as e:
                err_str = str(e)
                if "401" in err_str or "Unauthorized" in err_str:
                    print(f"\n\033[1;33m[🔒 401 UNAUTHORIZED]\033[0m Model '{active_model}' returned HTTP 401 Unauthorized.")
                    if ":cloud" in active_model.lower():
                        print("\033[2m    This is an upstream cloud proxy model. The server lacks upstream API keys or requires a client token.\033[0m")
                    print("\033[2m    Tip: Type /model to switch to an open local model (e.g. smollm2:135m, sysverify), or provide an API key.\033[0m")
                elif "404" in err_str or "not found" in err_str.lower():
                    print(f"\n\033[1;33m[404 NOT FOUND]\033[0m Model '{active_model}' not found on remote host {base_url}.")
                    print(f"\033[2m    Tip: Use '/pull {active_model}' or '/download {active_model}' to download it to the remote host.\033[0m")
                    try:
                        pull_now = input(f"Would you like to download/pull '{active_model}' on {base_url} now? [Y/n]: ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        pull_now = "n"
                        print()
                    if pull_now in ("", "y", "yes"):
                        ok, msg = pull_ollama_model(base_url, active_model, headers=headers, timeout=max(timeout, 600.0))
                        if ok:
                            print(f"\n[✔] {msg}")
                            tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                            updated_models = tags_res.get("models", [])
                            if not updated_models:
                                openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
                                updated_models = openai_res.get("models", [])
                            if updated_models:
                                models = updated_models
                                known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]
                            if active_model not in known_names:
                                known_names.append(active_model)
                            setup_readline(model_names=known_names)
                            print(f"[*] Model '{active_model}' is now ready. You can re-send your prompt.")
                        else:
                            print(f"\n[✘] Pull failed: {msg}")
                else:
                    print(f"\n[!] Chat completion error: {clean_error_message(err_str)}")

    finally:
        save_readline_history()
        cleanup_readline()

    return 0


def run_model(
    target: str,
    model: Optional[str] = None,
    prompt: Optional[str] = None,
    default_port: Optional[int] = None,
    timeout: float = 60.0,
    use_https: bool = False,
    api_key: Optional[str] = None,
    system_prompt: Optional[str] = None,
    auto_pull: bool = True,
) -> int:
    """
    Run an Ollama model:
      - If prompt is provided (or piped via stdin): executes single-turn query and streams reply.
      - If prompt is empty: launches interactive chat with that model.
      - If model is not found locally: attempts to pull it via /api/pull.
    """
    base_url, host, port = parse_target(target, default_port=default_port, use_https=use_https)

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # Fetch models from tags or openai
    tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
    models = tags_res.get("models", [])
    openai_res = None
    if not models:
        openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
        models = openai_res.get("models", [])

    if not models:
        unauth = tags_res.get("is_unauthorized") or (openai_res and openai_res.get("is_unauthorized"))
        if unauth:
            unauth_code = tags_res.get("status_code") or (openai_res.get("status_code") if openai_res else 401)
            print(f"\n[🔒] Target requires authentication (HTTP {unauth_code} Unauthorized / Forbidden).")
            try:
                entered_key = input("Enter API key / Bearer token (or press Enter to cancel): ").strip()
                if entered_key:
                    headers["Authorization"] = f"Bearer {entered_key}"
                    tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                    models = tags_res.get("models", [])
                    if not models:
                        openai_res = check_openai_models(base_url, timeout=5.0, headers=headers)
                        models = openai_res.get("models", [])
            except (KeyboardInterrupt, EOFError):
                print()
                return 1

    known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]

    # If no model specified, ask user to select or take first
    if not model:
        if not models:
            err_msg = tags_res.get("error") or (openai_res.get("error") if openai_res else "Empty registry")
            print(f"[!] No models found on {base_url}. Reason: {err_msg}", file=sys.stderr)
            return 1
        if prompt:
            model = known_names[0]
            print(f"[*] No model specified; defaulting to '{model}'")
        else:
            model = interactive_select_model(models)
            if not model:
                print("[*] Model selection cancelled. Exiting.")
                return 0

    # Match model name with or without :latest
    matched_model = model
    if model not in known_names:
        for kn in known_names:
            if kn == f"{model}:latest" or kn.split(":")[0] == model:
                matched_model = kn
                break

    if matched_model in known_names:
        model = matched_model
    else:
        # Model not in registry on the server
        if auto_pull:
            print(f"[*] Model '{model}' not found on {base_url}.")
            pull_ok, pull_msg = pull_ollama_model(base_url, model, headers=headers, timeout=max(timeout, 600.0))
            if pull_ok:
                tags_res = check_ollama_tags(base_url, timeout=5.0, headers=headers)
                models = tags_res.get("models", [])
                known_names = [m.get("name") or m.get("id") for m in models if m.get("name") or m.get("id")]
            else:
                print(f"[!] Pull failed: {pull_msg}", file=sys.stderr)
                print(f"[*] Proceeding with '{model}' in case server proxies it...", file=sys.stderr)

    # If prompt is provided, run single turn
    if prompt and prompt.strip():
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt.strip()})

        is_tty = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
        if is_tty:
            sys.stdout.write(f"\033[1;32m[{model}]\033[0m: ")
            sys.stdout.flush()

        try:
            reply, stats = stream_chat_turn(
                base_url=base_url,
                model=model,
                messages=messages,
                timeout=max(timeout, 120.0),
                headers=headers,
            )
            print()
            if is_tty:
                tok_s = stats["tokens_per_second"]
                toks = stats["tokens"]
                tot = stats["total_sec"]
                ttft = stats["ttft_ms"]
                print(f"\033[2m[⏱ {tot:.2f}s | {toks} tokens | {tok_s:.1f} tok/s | TTFT: {ttft:.0f}ms]\033[0m")
            return 0
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            return 130
        except Exception as e:
            err_str = str(e)
            if "401" in err_str or "Unauthorized" in err_str:
                print(f"\n\033[1;33m[🔒 401 UNAUTHORIZED]\033[0m Model '{model}' returned HTTP 401 Unauthorized.", file=sys.stderr)
            else:
                print(f"\n[!] Error: {clean_error_message(err_str)}", file=sys.stderr)
            return 1

    # No prompt provided: launch interactive chat session with this model
    return run_interactive_chat(
        target=target,
        default_port=default_port,
        timeout=max(timeout, 60.0),
        use_https=use_https,
        api_key=api_key,
        initial_model=model,
        system_prompt=system_prompt,
    )


def init_duckdb(db_path: str) -> Any:
    """Initialize DuckDB connection and ensure targets and models tables exist."""
    if not HAS_DUCKDB:
        raise RuntimeError("duckdb is not installed. Install via: pip install duckdb")

    conn = duckdb.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            base_url VARCHAR PRIMARY KEY,
            target VARCHAR,
            host VARCHAR,
            port INTEGER,
            scanned_at TIMESTAMP,
            status VARCHAR,
            version VARCHAR,
            tags_success BOOLEAN,
            openai_success BOOLEAN,
            chat_status VARCHAR,
            is_authorized BOOLEAN,
            is_unauthorized BOOLEAN,
            models_count INTEGER,
            models_list VARCHAR,
            latency_ms DOUBLE,
            speed_tok_s DOUBLE,
            error VARCHAR,
            report_json VARCHAR
        );
        CREATE INDEX IF NOT EXISTS idx_targets_host_port ON targets (host, port);
        CREATE INDEX IF NOT EXISTS idx_targets_target ON targets (target);

        CREATE TABLE IF NOT EXISTS models (
            base_url VARCHAR,
            target VARCHAR,
            host VARCHAR,
            port INTEGER,
            name VARCHAR,
            model_id VARCHAR,
            size_bytes BIGINT,
            parameter_size VARCHAR,
            quantization VARCHAR,
            format VARCHAR,
            family VARCHAR,
            modified_at VARCHAR,
            scanned_at TIMESTAMP,
            PRIMARY KEY (base_url, name)
        );
        CREATE INDEX IF NOT EXISTS idx_models_name ON models (name);
    """)
    conn.commit()
    return conn


def get_cached_target(
    conn: Any,
    target: str,
    default_port: Optional[int] = None,
    use_https: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Query DuckDB for an existing scan of the target host/port.
    Returns the loaded report dict if found, or None.
    """
    if default_port is None:
        default_port = get_default_port()
    try:
        base_url, host, port = parse_target(target, default_port=default_port, use_https=use_https)
    except Exception:
        scheme = "https" if use_https else "http"
        base_url, host, port = f"{scheme}://{target}:{default_port}", target, default_port

    query = """
        SELECT report_json, scanned_at, status
        FROM targets
        WHERE base_url = ? OR target = ? OR (host = ? AND port = ?)
        ORDER BY scanned_at DESC
        LIMIT 1
    """
    try:
        row = conn.execute(query, [base_url, target, host, port]).fetchone()
        if row and row[0]:
            report = json.loads(row[0])
            report["_cached"] = True
            report["_cached_at"] = str(row[1]) if row[1] else None
            report["target"] = target
            return report
    except Exception as e:
        sys.stderr.write(f"[!] Warning reading DuckDB cache for {target}: {e}\n")
    return None


def save_target_to_duckdb(conn: Any, report: Dict[str, Any]) -> None:
    """Persist target scan results and discovered models into DuckDB."""
    base_url = report.get("base_url") or ""
    target = report.get("target") or ""
    host = report.get("host") or ""
    port = report.get("port")

    if port is None or not host or not base_url:
        try:
            parsed_url, parsed_host, parsed_port = parse_target(target or base_url, default_port=port or get_default_port())
            if not base_url:
                base_url = parsed_url
            if not host:
                host = parsed_host
            if port is None:
                port = parsed_port
        except Exception:
            if port is None:
                port = get_default_port()
            if not host:
                host = target
            if not base_url:
                base_url = f"http://{host}:{port}"

    now = datetime.datetime.now(datetime.timezone.utc)
    status = format_target_status_brief(report)

    version_val = report.get("version")
    if isinstance(version_val, dict):
        version_val = version_val.get("version")
    elif version_val is not None:
        version_val = str(version_val)

    tags_api = report.get("tags_api") or {}
    tags_success = bool(tags_api.get("success", False))

    openai_api = report.get("openai_api") or {}
    openai_success = bool(openai_api.get("success", False))

    chat_auth = report.get("chat_auth") or {}
    chat_status = chat_auth.get("summary_status") or "N/A"
    is_authorized = bool(chat_auth.get("is_authorized", False))
    is_unauthorized = bool(
        chat_auth.get("is_unauthorized")
        or tags_api.get("is_unauthorized")
        or openai_api.get("is_unauthorized")
    )

    models_raw = tags_api.get("models") or openai_api.get("models") or []
    model_names: List[str] = []
    for m in models_raw:
        if isinstance(m, dict):
            name = m.get("name") or m.get("id")
            if name and name not in model_names:
                model_names.append(name)

    models_count = len(model_names)
    models_list = ", ".join(model_names)

    latency_ms = tags_api.get("latency_ms")
    if latency_ms is None:
        latency_ms = openai_api.get("latency_ms")

    chat_speed = report.get("chat_speed") or {}
    speed_tok_s = chat_speed.get("tokens_per_second") if chat_speed.get("success") else None

    error_val = report.get("error") or tags_api.get("error") or openai_api.get("error")

    clean_report = {k: v for k, v in report.items() if not k.startswith("_")}
    report_json = json.dumps(clean_report)

    try:
        conn.execute("""
            INSERT OR REPLACE INTO targets (
                base_url, target, host, port, scanned_at, status, version,
                tags_success, openai_success, chat_status, is_authorized, is_unauthorized,
                models_count, models_list, latency_ms, speed_tok_s, error, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            base_url, target, host, port, now, status, version_val,
            tags_success, openai_success, chat_status, is_authorized, is_unauthorized,
            models_count, models_list, latency_ms, speed_tok_s, error_val, report_json
        ])

        # Delete existing models for this host:port to keep cleanly synchronized
        conn.execute("DELETE FROM models WHERE base_url = ? OR (host = ? AND port = ?)", [base_url, host, port])
        for m in models_raw:
            if not isinstance(m, dict):
                continue
            m_name = m.get("name") or m.get("id") or "unknown"
            m_id = m.get("id") or m.get("digest") or ""
            m_size = m.get("size_bytes") if "size_bytes" in m else m.get("size")
            m_params = m.get("parameter_size") or ""
            m_quant = m.get("quantization_level") or m.get("quantization") or ""
            m_fmt = m.get("format") or m.get("details", {}).get("format") or ""
            m_family = m.get("family") or m.get("details", {}).get("family") or ""
            m_mod = m.get("modified_at") or ""
            conn.execute("""
                INSERT OR REPLACE INTO models (
                    base_url, target, host, port, name, model_id, size_bytes,
                    parameter_size, quantization, format, family, modified_at, scanned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                base_url, target, host, port, m_name, m_id, m_size,
                m_params, m_quant, m_fmt, m_family, str(m_mod), now
            ])

        conn.commit()
    except Exception as e:
        sys.stderr.write(f"[!] Warning writing to DuckDB ({base_url}): {e}\n")


def show_duckdb_summary(conn: Any, db_path: str) -> None:
    """Print statistical overview of the DuckDB database."""
    total_targets = conn.execute("SELECT count(*) FROM targets").fetchone()[0]
    if total_targets == 0:
        print(f"[*] Database '{db_path}' contains 0 target records.")
        return

    authorized = conn.execute("SELECT count(*) FROM targets WHERE is_authorized = true").fetchone()[0]
    unauthorized = conn.execute("SELECT count(*) FROM targets WHERE is_unauthorized = true").fetchone()[0]
    tags_ok = conn.execute("SELECT count(*) FROM targets WHERE tags_success = true").fetchone()[0]
    openai_ok = conn.execute("SELECT count(*) FROM targets WHERE openai_success = true").fetchone()[0]
    with_models = conn.execute("SELECT count(*) FROM targets WHERE models_count > 0").fetchone()[0]
    total_models = conn.execute("SELECT count(*) FROM models").fetchone()[0]
    unique_models = conn.execute("SELECT count(DISTINCT name) FROM models").fetchone()[0]
    latest_scan = conn.execute("SELECT max(scanned_at) FROM targets").fetchone()[0]

    top_models = conn.execute("""
        SELECT m.name, count(*) as cnt, sum(CASE WHEN t.is_authorized = true THEN 1 ELSE 0 END) as auth_cnt
        FROM models m
        LEFT JOIN targets t ON m.base_url = t.base_url
        GROUP BY m.name
        ORDER BY cnt DESC, m.name ASC
        LIMIT 10
    """).fetchall()

    if HAS_RICH:
        console = Console()
        summary_table = Table(title=f"DuckDB Summary: {db_path}", show_header=True)
        summary_table.add_column("Metric", style="bold cyan")
        summary_table.add_column("Value", style="bold green")

        summary_table.add_row("Total Scanned Targets", str(total_targets))
        pct_auth = f" ({authorized/total_targets*100:.1f}%)" if total_targets else ""
        pct_unauth = f" ({unauthorized/total_targets*100:.1f}%)" if total_targets else ""
        summary_table.add_row("Targets with Open Chat (Authorized)", f"{authorized}{pct_auth}")
        summary_table.add_row("Targets Unauthorized / Protected", f"{unauthorized}{pct_unauth}")
        summary_table.add_row("Targets with Native Tags API OK", str(tags_ok))
        summary_table.add_row("Targets with OpenAI API OK", str(openai_ok))
        summary_table.add_row("Targets with Discovered Models", str(with_models))
        summary_table.add_row("Total Model Instances Recorded", str(total_models))
        summary_table.add_row("Distinct Model Names", str(unique_models))
        summary_table.add_row("Latest Scan Recorded", str(latest_scan) if latest_scan else "N/A")
        console.print(summary_table)

        if top_models:
            models_table = Table(title="Top Discovered Models", show_header=True)
            models_table.add_column("Rank", style="dim", width=6)
            models_table.add_column("Model Name", style="bold yellow")
            models_table.add_column("Host Count", style="green", justify="right")
            models_table.add_column("Open/Authorized Hosts", style="cyan", justify="right")
            for r_idx, (m_name, m_cnt, m_auth) in enumerate(top_models, 1):
                models_table.add_row(str(r_idx), str(m_name), str(m_cnt), str(m_auth or 0))
            console.print(models_table)
    else:
        print(f"=== DuckDB Summary: {db_path} ===")
        print(f"  Total Scanned Targets:             {total_targets}")
        pct_auth = f" ({authorized/total_targets*100:.1f}%)" if total_targets else ""
        pct_unauth = f" ({unauthorized/total_targets*100:.1f}%)" if total_targets else ""
        print(f"  Targets with Open Chat (Auth OK):  {authorized}{pct_auth}")
        print(f"  Targets Unauthorized / Protected:  {unauthorized}{pct_unauth}")
        print(f"  Targets with Native Tags API OK:   {tags_ok}")
        print(f"  Targets with OpenAI API OK:        {openai_ok}")
        print(f"  Targets with Discovered Models:    {with_models}")
        print(f"  Total Model Instances Recorded:    {total_models}")
        print(f"  Distinct Model Names:              {unique_models}")
        print(f"  Latest Scan Recorded:              {latest_scan or 'N/A'}")
        if top_models:
            print("\n  Top Models:")
            for r_idx, (m_name, m_cnt, m_auth) in enumerate(top_models, 1):
                print(f"    [{r_idx}] {m_name:<30} {m_cnt} hosts ({m_auth or 0} open)")


def run_duckdb_query(conn: Any, query: str, as_json: bool = False) -> int:
    """Execute arbitrary SQL query against DuckDB and display results."""
    try:
        cursor = conn.execute(query)
        col_names = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = cursor.fetchall()
        if as_json:
            out = [dict(zip(col_names, r)) for r in rows]
            print(json.dumps(out, indent=2, default=str))
            return 0

        if not rows:
            print("[*] Query executed successfully. 0 rows returned.")
            return 0

        if HAS_RICH:
            console = Console()
            table = Table(title=f"DuckDB Query Result ({len(rows)} row{'s' if len(rows) != 1 else ''})", show_header=True)
            for col in col_names:
                table.add_column(col, style="cyan")
            for r in rows:
                table.add_row(*[str(v) if v is not None else "NULL" for v in r])
            console.print(table)
        else:
            print(" | ".join(col_names))
            print("-" * max(40, len(" | ".join(col_names))))
            for r in rows:
                print(" | ".join(str(v) if v is not None else "NULL" for v in r))
            print(f"\n({len(rows)} row{'s' if len(rows) != 1 else ''})")
        return 0
    except Exception as e:
        sys.stderr.write(f"[!] DuckDB Query Error: {e}\n")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ollama_cli",
        description="Ollama Probe, REST API Speed Evaluator & Interactive Chat CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s 127.0.0.1                     # Probe native & OpenAI REST APIs
  %(prog)s run smollm2:135m              # Run model (chat or prompt)
  %(prog)s run smollm2:135m "Why is the sky blue?"  # Single-turn prompt
  %(prog)s run 192.168.1.50 smollm2:135m # Run model on remote host
  %(prog)s pull llama3                   # Pull model from Ollama registry
  %(prog)s 127.0.0.1 --speed             # Evaluate REST API reply speed (tokens/sec)
  %(prog)s 127.0.0.1 --chat              # Interactive chat with model selector
  %(prog)s chat 127.0.0.1                # Interactive chat (subcommand syntax)
  %(prog)s 192.168.1.50:8080 --json      # Custom port target
  %(prog)s 192.168.1.50 8080             # Positional IP and port arguments
  %(prog)s 192.168.1.50:11434 --json     # Machine-readable JSON output
  %(prog)s --range 192.168.1.0/24        # Scan IP range (CIDR) for Ollama on port 11434
  %(prog)s -r 192.168.1.1-192.168.1.50  # Scan IP range (start-end)
  %(prog)s -r 192.168.1.1-50 -v -db     # Scan IP range with verbose ETA and DuckDB persistence
  %(prog)s -r 192.168.1.0/24 -o --quiet # Scan IP range testing only /v1/models (quiet summary)
  %(prog)s -f ips.txt --quiet            # Multi-host summary scan
  %(prog)s -f ips.txt -db                # Scan targets and memorize in DuckDB (queries DB first)
  %(prog)s -f ips.txt -db --force        # Force re-check of targets and update DuckDB
  %(prog)s --db-summary                  # Show summary statistics of DuckDB database
  %(prog)s --db-query "SELECT * FROM targets" # Query DuckDB database with SQL
  %(prog)s --dashboard                   # Launch web dashboard on port 2000
""",
    )

    default_cli_port = get_default_port()
    parser.add_argument(
        "ips",
        nargs="*",
        help="One or more target IPs or hostnames (e.g. 127.0.0.1, run <model>, chat <ip>).",
    )
    parser.add_argument(
        "-r", "--range", "--ip-range", "--range-ip",
        type=str,
        action="append",
        dest="ip_range",
        metavar="IP_RANGE",
        help="Scan a range of IP addresses for Ollama port 11434 and test /v1/models (e.g. 192.168.1.0/24, 192.168.1.1-192.168.1.50, 192.168.1.1-50, 192.168.1.*).",
    )
    parser.add_argument(
        "-T", "--threads", "--workers",
        type=int,
        default=1,
        metavar="NUM",
        help="Number of concurrent worker threads for scanning multiple targets or IP ranges (default: 1).",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=default_cli_port,
        help=f"Default port to connect to if not specified in target (default: {default_cli_port} or OLLAMA_PORT / OLLAMA_HOST).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS scheme instead of HTTP.",
    )
    parser.add_argument(
        "-k", "--api-key",
        type=str,
        default=os.getenv("OLLAMA_API_KEY") or os.getenv("OPENAI_API_KEY"),
        help="Optional API key / Bearer token (or set OLLAMA_API_KEY / OPENAI_API_KEY env var).",
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        dest="tags_only",
        help="Call only Ollama native list endpoint (/api/tags).",
    )
    parser.add_argument(
        "-o", "--openai",
        action="store_true",
        dest="openai_only",
        help="Test only OpenAI REST API models endpoint (/v1/models).",
    )
    parser.add_argument(
        "--check-chat", "--auth",
        action="store_true",
        dest="check_chat",
        help="Check whether Ollama chat endpoints (/api/chat and /v1/chat/completions) are authorized or open.",
    )
    parser.add_argument(
        "--no-chat-check",
        action="store_true",
        dest="no_chat_check",
        help="Disable checking chat endpoint authorization during probe.",
    )
    parser.add_argument(
        "-s", "--speed",
        action="store_true",
        dest="speed_test",
        help="Evaluate OpenAI REST API reply speed (/v1/chat/completions) in tokens/sec.",
    )
    parser.add_argument(
        "--speed-prompt",
        type=str,
        default="Explain in one sentence why the sky is blue.",
        help="Custom prompt for the speed evaluation benchmark.",
    )
    parser.add_argument(
        "--speed-tokens",
        type=int,
        default=30,
        help="Max tokens for speed evaluation (default: 30).",
    )
    parser.add_argument(
        "-c", "--chat",
        action="store_true",
        dest="chat_mode",
        help="Launch interactive chat session with model selection.",
    )
    parser.add_argument(
        "--run",
        type=str,
        nargs="?",
        const="",
        default=None,
        metavar="MODEL",
        help="Run a model directly (interactive chat or one-off prompt).",
    )
    parser.add_argument(
        "--pull",
        type=str,
        nargs="?",
        const="",
        default=None,
        metavar="MODEL",
        help="Pull a model from the Ollama registry.",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=None,
        help="Prompt text for non-interactive model execution.",
    )
    parser.add_argument(
        "--no-pull",
        action="store_true",
        dest="no_pull",
        help="Disable auto-pulling missing models when running.",
    )
    parser.add_argument(
        "-m", "--model",
        type=str,
        default=None,
        help="Specify model name for run, chat, or speed benchmark.",
    )
    parser.add_argument(
        "--system",
        type=str,
        default=None,
        help="System prompt for run or interactive chat.",
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Read target IPs from a file (one IP per line, or '-' for stdin).",
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        dest="json_output",
        help="Output raw JSON results.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Compact one-line summary output per host.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed diagnostic info (and live sliding ETA during multi-host scans).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable rich colored terminal output.",
    )
    parser.add_argument(
        "-db", "--db",
        nargs="?",
        const="ollama_targets.duckdb",
        default=None,
        metavar="DB_PATH",
        help="DuckDB database path to memorize scan results and query before scanning (default: ollama_targets.duckdb).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force network re-probing of target IP(s) even if already checked/cached in DuckDB.",
    )
    parser.add_argument(
        "--db-summary",
        action="store_true",
        help="Display summary statistics and top models from DuckDB database and exit.",
    )
    parser.add_argument(
        "--db-query",
        type=str,
        metavar="SQL",
        help="Execute arbitrary SQL query against DuckDB database and display results.",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch web dashboard on port 2000 to read, filter, and search in DuckDB database.",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=2000,
        help="Port number for web dashboard (default: 2000).",
    )

    args = parser.parse_args()

    # If -db consumed an IP, host target, or IP range due to nargs="?" positional behavior:
    raw_tokens = list(args.ips)
    if args.db and not args.db.endswith((".duckdb", ".db")):
        if is_ip_range(args.db) or (is_ip_or_host(args.db) and "/" not in args.db):
            raw_tokens.insert(0, args.db)
            args.db = "ollama_targets.duckdb"

    # Validate DuckDB library availability if DB operations were requested
    if (args.db or args.db_summary or args.db_query or args.dashboard) and not HAS_DUCKDB:
        print("[!] Error: 'duckdb' Python library is required for database operations.\n    Install it via: pip install duckdb", file=sys.stderr)
        return 1

    # Handle --dashboard launch directly
    if args.dashboard:
        db_file = args.db or "ollama_targets.duckdb"
        from web_dashboard import run_server
        return run_server(port=args.dashboard_port, db_path=db_file)

    # Handle --db-summary or --db-query directly without requiring target hosts
    if args.db_summary or args.db_query:
        db_file = args.db or "ollama_targets.duckdb"
        if not os.path.exists(db_file):
            print(f"[!] Error: DuckDB database '{db_file}' does not exist. Run a scan with -db first.", file=sys.stderr)
            return 1
        db_conn = init_duckdb(db_file)
        try:
            if args.db_summary:
                show_duckdb_summary(db_conn, db_file)
                return 0
            if args.db_query:
                return run_duckdb_query(db_conn, args.db_query, as_json=args.json_output)
        finally:
            db_conn.close()

    # Detect if user used `run`, `pull`, `chat`, or `auth` as positional syntax
    run_mode = args.run is not None
    run_model_name = (args.run if args.run else None) or args.model
    pull_mode = args.pull is not None
    pull_model_name = (args.pull if args.pull else None)
    chat_mode = args.chat_mode
    cli_prompt = args.prompt or ""

    cleaned_tokens: List[str] = []
    for token in raw_tokens:
        token_lower = token.lower()
        if token_lower == "run":
            run_mode = True
        elif token_lower == "pull":
            pull_mode = True
        elif token_lower == "chat":
            chat_mode = True
        elif token_lower in ("check-chat", "auth", "check_chat"):
            args.check_chat = True
        else:
            cleaned_tokens.append(token)

    # Detect target IP if any
    target_ip = None
    for i, t in enumerate(cleaned_tokens):
        if is_ip_or_host(t):
            target_ip = cleaned_tokens.pop(i)
            # If next token is a port number (e.g. `192.168.1.50 8080`), pair it with the IP
            if i < len(cleaned_tokens) and cleaned_tokens[i].isdigit() and 1 <= int(cleaned_tokens[i]) <= 65535 and ":" not in target_ip:
                port_token = cleaned_tokens.pop(i)
                target_ip = f"{target_ip}:{port_token}"
            break

    # If run, pull, or chat mode was requested but no IP was specified, default to OLLAMA_HOST or 127.0.0.1
    if not target_ip and (run_mode or pull_mode or chat_mode):
        target_ip = os.getenv("OLLAMA_HOST") or "127.0.0.1"

    # Handle `run` mode
    if run_mode:
        if not run_model_name and cleaned_tokens:
            run_model_name = cleaned_tokens.pop(0)
        if cleaned_tokens and not cli_prompt:
            cli_prompt = " ".join(cleaned_tokens)
        if not cli_prompt and not sys.stdin.isatty():
            try:
                piped = sys.stdin.read().strip()
                if piped:
                    cli_prompt = piped
            except Exception:
                pass

        return run_model(
            target=target_ip,
            model=run_model_name,
            prompt=cli_prompt,
            default_port=args.port,
            timeout=max(args.timeout, 60.0),
            use_https=args.https,
            api_key=args.api_key,
            system_prompt=args.system,
            auto_pull=not args.no_pull,
        )

    # Handle `pull` mode
    if pull_mode:
        if not pull_model_name and cleaned_tokens:
            pull_model_name = cleaned_tokens.pop(0)
        if not pull_model_name:
            print("[!] Error: No model name specified to pull. Usage: `ollama_cli.py pull <model>`", file=sys.stderr)
            return 1
        base_url, host, port = parse_target(target_ip, default_port=args.port, use_https=args.https)
        headers = {"Authorization": f"Bearer {args.api_key}"} if args.api_key else None
        ok, msg = pull_ollama_model(base_url=base_url, model=pull_model_name, headers=headers, timeout=max(args.timeout, 600.0))
        if ok:
            print(f"[✔] {msg}")
            return 0
        else:
            print(f"[✘] {msg}", file=sys.stderr)
            return 1

    # Pair any remaining (host, port) tokens (e.g. `1.1.1.1 8080 2.2.2.2 9000`)
    paired_tokens: List[str] = []
    idx = 0
    while idx < len(cleaned_tokens):
        curr = cleaned_tokens[idx]
        if is_ip_or_host(curr) and ":" not in curr and (idx + 1) < len(cleaned_tokens) and cleaned_tokens[idx + 1].isdigit() and 1 <= int(cleaned_tokens[idx + 1]) <= 65535:
            paired_tokens.append(f"{curr}:{cleaned_tokens[idx + 1]}")
            idx += 2
        else:
            paired_tokens.append(curr)
            idx += 1

    targets: List[str] = []
    if target_ip:
        targets.append(target_ip)
    targets.extend(paired_tokens)

    # Read from file or stdin if specified (-f)
    if args.file:
        if args.file == "-":
            for line in sys.stdin:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        else:
            try:
                with open(args.file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            targets.append(line)
            except Exception as e:
                print(f"Error reading file '{args.file}': {e}", file=sys.stderr)
                return 1

    # Include explicit ranges from -r / --range
    expanded_targets: List[str] = []
    if args.ip_range:
        for r_item in args.ip_range:
            try:
                parsed_ips = parse_ip_range(r_item)
                if not parsed_ips:
                    print(f"[!] Error: Could not parse any valid IP addresses from range '{r_item}'.", file=sys.stderr)
                    return 1
                expanded_targets.extend(parsed_ips)
            except ValueError as e:
                print(f"[!] Error parsing IP range '{r_item}': {e}", file=sys.stderr)
                return 1

    # Expand any IP ranges passed positionally or via file
    for t in targets:
        if is_ip_range(t):
            try:
                expanded_targets.extend(parse_ip_range(t))
            except ValueError as e:
                print(f"[!] Error parsing IP range '{t}': {e}", file=sys.stderr)
                return 1
        else:
            expanded_targets.append(t)

    targets = expanded_targets

    if not targets:
        parser.print_help()
        print("\n[ERROR] No target IP provided. Specify at least one IP on the command line (e.g. `python3 ollama_cli.py 127.0.0.1` or `python3 ollama_cli.py --range 192.168.1.0/24`).", file=sys.stderr)
        return 1

    # If interactive chat mode requested
    if chat_mode:
        target = targets[0]
        initial_model = args.model
        if not initial_model and len(targets) > 1 and not is_ip_or_host(targets[1]):
            initial_model = targets[1]
        return run_interactive_chat(
            target=target,
            default_port=args.port,
            timeout=max(args.timeout, 60.0),
            use_https=args.https,
            api_key=args.api_key,
            initial_model=initial_model,
            system_prompt=args.system,
        )

    run_tags = True
    run_openai = True
    run_chat_auth = not args.no_chat_check

    if args.tags_only and not args.openai_only and not args.check_chat:
        run_openai = False
        run_chat_auth = False
    elif args.openai_only and not args.tags_only and not args.check_chat:
        run_tags = False
        run_chat_auth = False

    reports = []
    has_failure = False

    is_multi_host = len(targets) > 1 or bool(args.file) or bool(args.ip_range)
    show_verbose_progress = is_multi_host and args.verbose

    db_conn = None
    if args.db:
        try:
            db_conn = init_duckdb(args.db)
            if args.verbose and not show_verbose_progress:
                sys.stderr.write(f"[*] DuckDB persistence enabled: {args.db}\n")
        except Exception as e:
            sys.stderr.write(f"[!] Error initializing DuckDB '{args.db}': {e}\n")
            return 1

    if show_verbose_progress:
        db_tag = f" [DuckDB: {args.db}{' (force)' if args.force else ''}]" if args.db else ""
        sys.stderr.write(f"[*] Starting multi-host scan for {len(targets)} targets{db_tag} (verbose mode)...\n")
        sys.stderr.flush()

    sliding_eta = SlidingETA(total_items=len(targets), window_size=10) if show_verbose_progress else None
    db_lock = threading.Lock()
    progress_lock = threading.Lock()

    def process_target_item(target: str) -> Tuple[Dict[str, Any], bool, float]:
        host_start = time.perf_counter()
        is_cached = False
        report = None

        # Query DuckDB first unless --force is specified
        if db_conn and not args.force:
            with db_lock:
                cached_report = get_cached_target(db_conn, target, default_port=args.port, use_https=args.https)
            if cached_report:
                is_cached = True
                report = cached_report
                if args.verbose and not show_verbose_progress:
                    sys.stderr.write(f"[*] Target {target} loaded from DuckDB cache ({args.db}). Use --force to re-probe.\n")

        if not is_cached:
            try:
                report = probe_target(
                    target=target,
                    default_port=args.port,
                    timeout=args.timeout,
                    use_https=args.https,
                    api_key=args.api_key,
                    run_tags=run_tags,
                    run_openai=run_openai,
                    run_chat_auth=run_chat_auth,
                    run_speed=args.speed_test,
                    selected_model=args.model,
                    speed_prompt=args.speed_prompt,
                    speed_tokens=args.speed_tokens,
                )
                if db_conn:
                    with db_lock:
                        save_target_to_duckdb(db_conn, report)
                    if args.verbose and not show_verbose_progress:
                        if args.force:
                            sys.stderr.write(f"[*] Target {target} re-probed (--force) and updated in DuckDB ({args.db}).\n")
                        else:
                            sys.stderr.write(f"[*] Target {target} saved to DuckDB ({args.db}).\n")

            except Exception as e:
                try:
                    err_base_url, err_host, err_port = parse_target(target, default_port=args.port, use_https=args.https)
                except Exception:
                    err_scheme = "https" if args.https else "http"
                    err_host = target
                    err_port = args.port
                    err_base_url = f"{err_scheme}://{err_host}:{err_port}"
                report = {
                    "target": target,
                    "base_url": err_base_url,
                    "host": err_host,
                    "port": err_port,
                    "error": str(e),
                    "tags_api": {"success": False, "error": str(e)},
                    "openai_api": {"success": False, "error": str(e)},
                    "chat_auth": {"is_authorized": False, "is_unauthorized": False, "summary_status": "ERROR", "error": str(e)} if run_chat_auth else None,
                    "chat_speed": {"success": False, "error": str(e)} if args.speed_test else None,
                }
                if db_conn:
                    with db_lock:
                        save_target_to_duckdb(db_conn, report)

        host_duration = time.perf_counter() - host_start
        return report, is_cached, host_duration

    def is_report_failed(rep: Dict[str, Any]) -> bool:
        if run_tags and (not rep.get("tags_api") or not rep["tags_api"].get("success")):
            return True
        if run_openai and (not rep.get("openai_api") or not rep["openai_api"].get("success")):
            return True
        if run_chat_auth and rep.get("chat_auth") and rep["chat_auth"].get("is_unauthorized"):
            return True
        if args.speed_test and (not rep.get("chat_speed") or not rep["chat_speed"].get("success")):
            return True
        return False

    try:
        num_workers = getattr(args, "threads", 1) or 1
        if num_workers > 1 and len(targets) > 1:
            worker_count = min(num_workers, len(targets))
            ordered_reports: List[Optional[Dict[str, Any]]] = [None] * len(targets)
            completed_items = 0

            def worker_fn(idx_0: int, tgt: str):
                nonlocal has_failure, completed_items
                rep, cached, dur = process_target_item(tgt)
                ordered_reports[idx_0] = rep
                if is_report_failed(rep):
                    has_failure = True

                if show_verbose_progress and sliding_eta:
                    with progress_lock:
                        completed_items += 1
                        current_num = completed_items
                        sliding_eta.record_item(dur)
                        status_brief = format_target_status_brief(rep)
                        rate_str = f"{sliding_eta.sliding_rate:.2f}s/host"
                        pct = (current_num / len(targets)) * 100.0
                        cached_label = " [cached in DB]" if cached else ""
                        msg = (
                            f"[*] [{current_num}/{len(targets)}] ({pct:.1f}%) Processed IP: {tgt}{cached_label} ({dur:.2f}s) - "
                            f"[{status_brief}] | Elapsed: {sliding_eta.format_elapsed()} | Slide ETA: {sliding_eta.format_eta()} ({rate_str})\n"
                        )
                        sys.stderr.write(msg)
                        sys.stderr.flush()

            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [executor.submit(worker_fn, i, t) for i, t in enumerate(targets)]
                concurrent.futures.wait(futures)

            reports = [r for r in ordered_reports if r is not None]
        else:
            for idx, target in enumerate(targets, 1):
                report, is_cached, host_duration = process_target_item(target)
                reports.append(report)
                if is_report_failed(report):
                    has_failure = True

                if show_verbose_progress and sliding_eta:
                    sliding_eta.record_item(host_duration)
                    status_brief = format_target_status_brief(report)
                    rate_str = f"{sliding_eta.sliding_rate:.2f}s/host"
                    pct = (idx / len(targets)) * 100.0
                    cached_label = " [cached in DB]" if is_cached else ""

                    msg = (
                        f"[*] [{idx}/{len(targets)}] ({pct:.1f}%) Processed IP: {target}{cached_label} ({host_duration:.2f}s) - "
                        f"[{status_brief}] | Elapsed: {sliding_eta.format_elapsed()} | Slide ETA: {sliding_eta.format_eta()} ({rate_str})\n"
                    )
                    sys.stderr.write(msg)
                    sys.stderr.flush()

        if show_verbose_progress and sliding_eta:
            total_time = sliding_eta.format_elapsed()
            sys.stderr.write(f"[*] Multi-host scan complete: {len(targets)} IPs processed in {total_time}.\n\n")
            sys.stderr.flush()

        if args.json_output:
            print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
        elif args.quiet:
            render_report_quiet(reports)
        else:
            if HAS_RICH and not args.no_color:
                render_report_rich(reports, verbose=args.verbose)
            else:
                render_report_plain(reports, verbose=args.verbose)

        return 1 if has_failure else 0

    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Scan interrupted by user.\n")
        if reports:
            if args.json_output:
                print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
            elif args.quiet:
                render_report_quiet(reports)
            else:
                if HAS_RICH and not args.no_color:
                    render_report_rich(reports, verbose=args.verbose)
                else:
                    render_report_plain(reports, verbose=args.verbose)
        return 130

    finally:
        if db_conn:
            try:
                db_conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
