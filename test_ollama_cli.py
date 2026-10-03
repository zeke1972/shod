#!/usr/bin/env python3
"""
Unit tests for ollama_cli.py
"""

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from ollama_cli import (
    SLASH_COMMANDS,
    check_chat_authorization,
    check_single_chat_endpoint,
    cleanup_readline,
    clean_error_message,
    complete_filepath,
    evaluate_chat_speed,
    format_bytes,
    format_duration,
    format_target_status_brief,
    format_time_ago,
    get_default_port,
    get_user_chat_input,
    interactive_select_model,
    is_ip_or_host,
    is_ip_range,
    load_file_for_chat,
    make_chat_completer,
    MAX_RANGE_HOSTS,
    parse_auth_error,
    parse_file_command_args,
    parse_ip_range,
    parse_target,
    probe_target,
    pull_ollama_model,
    run_interactive_chat,
    run_model,
    save_readline_history,
    setup_readline,
    SlidingETA,
    HAS_DUCKDB,
    init_duckdb,
    get_cached_target,
    save_target_to_duckdb,
    show_duckdb_summary,
    run_duckdb_query,
)


class TestTargetParsing(unittest.TestCase):
    def test_simple_ip(self):
        url, host, port = parse_target("127.0.0.1")
        self.assertEqual(url, "http://127.0.0.1:11434")
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 11434)

    def test_ip_with_port(self):
        url, host, port = parse_target("192.168.1.100:8080")
        self.assertEqual(url, "http://192.168.1.100:8080")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 8080)

    def test_url_with_scheme(self):
        url, host, port = parse_target("http://10.0.0.5:11434")
        self.assertEqual(url, "http://10.0.0.5:11434")
        self.assertEqual(host, "10.0.0.5")
        self.assertEqual(port, 11434)

    def test_https_target(self):
        url, host, port = parse_target("https://ollama.local:8443")
        self.assertEqual(url, "https://ollama.local:8443")
        self.assertEqual(host, "ollama.local")
        self.assertEqual(port, 8443)

    def test_ipv6_brackets(self):
        url, host, port = parse_target("[::1]:11434")
        self.assertEqual(url, "http://[::1]:11434")
        self.assertEqual(host, "::1")
        self.assertEqual(port, 11434)

    def test_custom_default_port(self):
        url, host, port = parse_target("127.0.0.1", default_port=9000)
        self.assertEqual(url, "http://127.0.0.1:9000")
        self.assertEqual(port, 9000)

    def test_ip_with_space_port(self):
        url, host, port = parse_target("192.168.1.100 8080")
        self.assertEqual(url, "http://192.168.1.100:8080")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 8080)

    def test_ip_with_comma_port(self):
        url, host, port = parse_target("192.168.1.100,8080")
        self.assertEqual(url, "http://192.168.1.100:8080")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 8080)

    def test_ip_with_tab_port(self):
        url, host, port = parse_target("192.168.1.100\t8080")
        self.assertEqual(url, "http://192.168.1.100:8080")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 8080)

    def test_ip_with_trailing_slash(self):
        url, host, port = parse_target("http://192.168.1.100:8080/")
        self.assertEqual(url, "http://192.168.1.100:8080")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 8080)

        url2, host2, port2 = parse_target("192.168.1.100:8080/")
        self.assertEqual(url2, "http://192.168.1.100:8080")
        self.assertEqual(host2, "192.168.1.100")
        self.assertEqual(port2, 8080)

    def test_env_ollama_port(self):
        with patch.dict(os.environ, {"OLLAMA_PORT": "8085"}):
            self.assertEqual(get_default_port(), 8085)
            url, host, port = parse_target("10.0.0.1")
            self.assertEqual(port, 8085)
            self.assertEqual(url, "http://10.0.0.1:8085")

    def test_env_ollama_host(self):
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://myhost:9090"}):
            self.assertEqual(get_default_port(), 9090)
            url, host, port = parse_target("10.0.0.2")
            self.assertEqual(port, 9090)
            self.assertEqual(url, "http://10.0.0.2:9090")


class TestFormatHelpers(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(None), "N/A")
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1024), "1 KB")
        self.assertEqual(format_bytes(1048576), "1 MB")
        self.assertEqual(format_bytes(10918038640), "10.17 GB")

    def test_format_time_ago(self):
        self.assertEqual(format_time_ago(None), "N/A")
        self.assertEqual(format_time_ago(""), "N/A")
        self.assertTrue(isinstance(format_time_ago("2026-01-01T12:00:00Z"), str))

    def test_clean_error_message(self):
        self.assertIn("Connection refused", clean_error_message("Error: [Errno 111] Connection refused"))
        self.assertIn("timed out", clean_error_message("Connection timed out after 5s"))
        self.assertIn("DNS resolution", clean_error_message("Name or service not known"))


class TestAuthHandling(unittest.TestCase):
    def test_parse_auth_error_openai_dict(self):
        msg = parse_auth_error(401, {"error": {"message": "Invalid API key provided"}})
        self.assertEqual(msg, "Invalid API key provided")

    def test_parse_auth_error_detail(self):
        msg = parse_auth_error(401, {"detail": "Missing Bearer token"})
        self.assertEqual(msg, "Missing Bearer token")

    def test_parse_auth_error_forbidden(self):
        msg = parse_auth_error(403, {"error": "Access Denied"})
        self.assertEqual(msg, "Access Denied")

    def test_parse_auth_error_fallback(self):
        msg = parse_auth_error(401, None)
        self.assertIn("Authentication credentials", msg)

    def test_mock_server_unauthorized_detection(self):
        """Spin up mock HTTP server returning 401 and verify CLI marks as unauthorized."""
        class MockAuthServer(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization")
                if auth == "Bearer valid-token":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    if "/api/tags" in self.path:
                        self.wfile.write(json.dumps({"models": [{"name": "auth-model:latest"}]}).encode())
                    else:
                        self.wfile.write(json.dumps({"object": "list", "data": [{"id": "auth-model:latest"}]}).encode())
                else:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": {"message": "Invalid or missing Bearer token"}}).encode())

            def do_POST(self):
                auth = self.headers.get("Authorization")
                if auth == "Bearer valid-token":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"id": "chat-1", "message": {"content": "pong"}}).encode())
                else:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": {"message": "Invalid or missing Bearer token"}}).encode())

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MockAuthServer)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            # Without token: should detect unauthorized
            report = probe_target(f"127.0.0.1:{port}", timeout=2.0)
            self.assertTrue(report["auth_required"])
            self.assertTrue(report["openai_api"]["is_unauthorized"])
            self.assertTrue(report["tags_api"]["is_unauthorized"])
            self.assertTrue(report["chat_auth"]["is_unauthorized"])
            self.assertEqual(report["chat_auth"]["summary_status"], "UNAUTHORIZED")
            self.assertIn("401 Unauthorized", report["openai_api"]["error"])
            self.assertIn("Invalid or missing Bearer token", report["openai_api"]["error"])

            # With token: should succeed
            report_auth = probe_target(f"127.0.0.1:{port}", timeout=2.0, api_key="valid-token")
            self.assertFalse(report_auth["auth_required"])
            self.assertTrue(report_auth["openai_api"]["success"])
            self.assertTrue(report_auth["tags_api"]["success"])
            self.assertTrue(report_auth["chat_auth"]["is_authorized"])
            self.assertEqual(report_auth["chat_auth"]["summary_status"], "AUTHENTICATED")
        finally:
            server.shutdown()
            server.server_close()


class TestModelSelection(unittest.TestCase):
    def test_interactive_select_default(self):
        models = [
            {"name": "model-a:latest", "id": "aaaa"},
            {"name": "model-b:latest", "id": "bbbb"},
        ]
        with patch("builtins.input", return_value=""):
            selected = interactive_select_model(models)
            self.assertEqual(selected, "model-a:latest")

    def test_interactive_select_second(self):
        models = [
            {"name": "model-a:latest", "id": "aaaa"},
            {"name": "model-b:latest", "id": "bbbb"},
        ]
        with patch("builtins.input", return_value="2"):
            selected = interactive_select_model(models)
            self.assertEqual(selected, "model-b:latest")

    def test_interactive_select_quit(self):
        models = [{"name": "model-a:latest"}]
        with patch("builtins.input", return_value="q"):
            selected = interactive_select_model(models)
            self.assertIsNone(selected)


class TestLiveProbe(unittest.TestCase):
    def test_probe_local_ollama(self):
        report = probe_target("127.0.0.1", timeout=3.0)
        self.assertEqual(report["host"], "127.0.0.1")
        self.assertEqual(report["port"], 11434)
        self.assertIsNotNone(report["tags_api"])
        self.assertTrue(report["tags_api"]["success"])
        self.assertGreater(len(report["tags_api"]["models"]), 0)

        self.assertIsNotNone(report["openai_api"])
        self.assertTrue(report["openai_api"]["success"])
        self.assertTrue(report["openai_api"]["is_openai_compatible"])
        self.assertGreater(len(report["openai_api"]["models"]), 0)

        # Model parity check
        self.assertTrue(report["models_match"])

    def test_evaluate_chat_speed(self):
        report = probe_target("127.0.0.1", timeout=3.0)
        first_model = report["tags_api"]["models"][0]["name"]
        speed_res = evaluate_chat_speed(
            base_url="http://127.0.0.1:11434",
            model=first_model,
            prompt="Reply with one word: Pong.",
            max_tokens=5,
            timeout=60.0,
        )
        self.assertTrue(speed_res["success"])
        self.assertEqual(speed_res["status_code"], 200)
        self.assertGreater(speed_res["completion_tokens"], 0)
        self.assertGreater(speed_res["tokens_per_second"], 0.0)


class TestChatAuthorization(unittest.TestCase):
    def test_local_chat_authorization_open(self):
        auth_res = check_chat_authorization("http://127.0.0.1:11434")
        self.assertEqual(auth_res["summary_status"], "OPEN")
        self.assertTrue(auth_res["is_authorized"])
        self.assertFalse(auth_res["is_unauthorized"])
        self.assertTrue(auth_res["native_chat"]["is_authorized"])
        self.assertTrue(auth_res["openai_chat"]["is_authorized"])

    def test_chat_auth_mock_unauthorized(self):
        class Mock401Server(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": {"message": "Bearer token required"}}')

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Mock401Server)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            auth_res = check_chat_authorization(f"http://127.0.0.1:{port}", timeout=2.0)
            self.assertEqual(auth_res["summary_status"], "UNAUTHORIZED")
            self.assertFalse(auth_res["is_authorized"])
            self.assertTrue(auth_res["is_unauthorized"])
            self.assertTrue(auth_res["native_chat"]["is_unauthorized"])
            self.assertTrue(auth_res["openai_chat"]["is_unauthorized"])
            self.assertIn("Bearer token required", auth_res["native_chat"]["message"])
        finally:
            server.shutdown()
            server.server_close()

    def test_chat_auth_mock_forbidden(self):
        class Mock403Server(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Forbidden IP"}')

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Mock403Server)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            auth_res = check_chat_authorization(f"http://127.0.0.1:{port}", timeout=2.0)
            self.assertEqual(auth_res["summary_status"], "FORBIDDEN")
            self.assertTrue(auth_res["is_unauthorized"])
            self.assertFalse(auth_res["is_authorized"])
        finally:
            server.shutdown()
            server.server_close()

    def test_chat_auth_mock_authenticated(self):
        class MockAuthServer(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                auth = self.headers.get("Authorization")
                if auth == "Bearer valid-key":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"id": "c1", "message": {"content": "ok"}}')
                else:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "Unauthorized"}')

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MockAuthServer)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            auth_res = check_chat_authorization(
                f"http://127.0.0.1:{port}",
                timeout=2.0,
                headers={"Authorization": "Bearer valid-key"},
            )
            self.assertEqual(auth_res["summary_status"], "AUTHENTICATED")
            self.assertTrue(auth_res["is_authorized"])
            self.assertFalse(auth_res["is_unauthorized"])
        finally:
            server.shutdown()
            server.server_close()

    def test_chat_auth_mock_partial(self):
        """Verify that when cloud models return 401 and local models return 200, status is PARTIAL."""
        class MockPartialServer(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode()
                if "auth_probe" in body:
                    # Gateway does not reject dummy model
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "model \'auth_probe\' not found"}')
                elif "cloud" in body:
                    # Cloud model returns 401
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "Unauthorized"}')
                else:
                    # Local model returns 200
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"id": "c1", "choices": [{"message": {"content": "hi"}}]}')

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MockPartialServer)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            avail = [
                {"name": "local-small:latest", "size": 100000, "details": {"format": "gguf"}},
                {"name": "kimi:cloud", "size": 380, "details": {"format": ""}},
            ]
            auth_res = check_chat_authorization(
                f"http://127.0.0.1:{port}",
                available_models=avail,
                timeout=2.0,
            )
            self.assertEqual(auth_res["summary_status"], "PARTIAL")
            self.assertTrue(auth_res["cloud_models_unauthorized"])
            self.assertTrue(auth_res["local_models_open"])

            # Probing specific cloud model directly
            cloud_res = check_chat_authorization(
                f"http://127.0.0.1:{port}",
                model="kimi:cloud",
                timeout=2.0,
            )
            self.assertEqual(cloud_res["summary_status"], "UNAUTHORIZED")
            self.assertTrue(cloud_res["is_unauthorized"])

            # Probing specific local model directly
            local_res = check_chat_authorization(
                f"http://127.0.0.1:{port}",
                model="local-small:latest",
                timeout=2.0,
            )
            self.assertEqual(local_res["summary_status"], "OPEN")
            self.assertTrue(local_res["is_authorized"])
        finally:
            server.shutdown()
            server.server_close()

    def test_live_probe_138_201_222_238(self):
        """Verify against actual host 138.201.222.238 to prevent false positives."""
        report = probe_target("138.201.222.238", timeout=4.0)
        self.assertEqual(report["chat_auth"]["summary_status"], "PARTIAL")
        self.assertTrue(report["chat_auth"]["cloud_models_unauthorized"])
        self.assertTrue(report["chat_auth"]["local_models_open"])

        # Specific cloud model: should detect 401 UNAUTHORIZED
        report_cloud = probe_target("138.201.222.238", selected_model="kimi-k2.7-code:cloud", timeout=4.0)
        self.assertEqual(report_cloud["chat_auth"]["summary_status"], "UNAUTHORIZED")
        self.assertTrue(report_cloud["chat_auth"]["is_unauthorized"])

        # Specific local model: should detect OPEN
        report_local = probe_target("138.201.222.238", selected_model="smollm2:135m", timeout=4.0)
        self.assertEqual(report_local["chat_auth"]["summary_status"], "OPEN")
        self.assertTrue(report_local["chat_auth"]["is_authorized"])


class TestCliSubprocess(unittest.TestCase):
    def test_cli_help(self):
        res = subprocess.run([sys.executable, "/home/chain/shod/ollama_cli.py", "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Ollama Probe", res.stdout)
        self.assertIn("--speed", res.stdout)
        self.assertIn("--chat", res.stdout)

    def test_cli_live_json(self):
        res = subprocess.run([sys.executable, "/home/chain/shod/ollama_cli.py", "127.0.0.1", "--json"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["host"], "127.0.0.1")
        self.assertTrue(data["tags_api"]["success"])
        self.assertTrue(data["openai_api"]["success"])

    def test_cli_positional_ip_and_port(self):
        res = subprocess.run([sys.executable, "/home/chain/shod/ollama_cli.py", "127.0.0.1", "11434", "--json"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["host"], "127.0.0.1")
        self.assertEqual(data["port"], 11434)
        self.assertEqual(data["base_url"], "http://127.0.0.1:11434")

    def test_cli_colon_ip_and_port(self):
        res = subprocess.run([sys.executable, "/home/chain/shod/ollama_cli.py", "127.0.0.1:11434", "--json"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["host"], "127.0.0.1")
        self.assertEqual(data["port"], 11434)
        self.assertEqual(data["base_url"], "http://127.0.0.1:11434")

    def test_cli_live_quiet(self):
        res = subprocess.run([sys.executable, "/home/chain/shod/ollama_cli.py", "127.0.0.1", "--quiet"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("127.0.0.1", res.stdout)
        self.assertIn("OK", res.stdout)

    def test_cli_speed_quiet(self):
        res = subprocess.run([
            sys.executable, "/home/chain/shod/ollama_cli.py", "127.0.0.1",
            "--speed", "--speed-tokens", "3", "--timeout", "60.0", "--quiet"
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("t/s", res.stdout)

    def test_cli_auth_shortcut(self):
        res = subprocess.run([sys.executable, "/home/chain/shod/ollama_cli.py", "auth", "127.0.0.1", "--json"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["chat_auth"]["summary_status"], "OPEN")
        self.assertTrue(data["chat_auth"]["is_authorized"])

    def test_cli_check_chat_quiet(self):
        res = subprocess.run([sys.executable, "/home/chain/shod/ollama_cli.py", "127.0.0.1", "--check-chat", "--quiet"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("CHAT", res.stdout)
        self.assertIn("OPEN", res.stdout)

    def test_cli_chat_exit(self):
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/ollama_cli.py", "chat", "127.0.0.1"],
            input="1\n/exit\n",
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Connected to Ollama REST API", res.stdout)
        self.assertIn("Goodbye", res.stdout)

    def test_cli_chat_help_and_exit(self):
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/ollama_cli.py", "chat", "127.0.0.1"],
            input="1\n/help\n/exit\n",
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("/file", res.stdout)
        self.assertIn("/paste", res.stdout)
        self.assertIn("Trailing '\\'", res.stdout)
        self.assertIn("Goodbye", res.stdout)

    def test_cli_chat_file_command(self):
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/ollama_cli.py", "chat", "127.0.0.1", "-m", "smollm2:135m"],
            input="/file\n/exit\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Usage: /file", res.stdout)
        self.assertIn("Goodbye", res.stdout)

    def test_cli_run_single_prompt(self):
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/ollama_cli.py", "run", "127.0.0.1", "smollm2:135m", "Hi"],
            capture_output=True,
            text=True,
            timeout=45,
        )
        self.assertEqual(res.returncode, 0)
        self.assertTrue(len(res.stdout.strip()) > 0)

    def test_cli_run_piped_prompt(self):
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/ollama_cli.py", "run", "127.0.0.1", "smollm2:135m"],
            input="Hello world\n",
            capture_output=True,
            text=True,
            timeout=45,
        )
        self.assertEqual(res.returncode, 0)
        self.assertTrue(len(res.stdout.strip()) > 0)

    def test_cli_pull_missing_model(self):
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/ollama_cli.py", "pull", "127.0.0.1", "fake_model_for_test_xyz"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Pulling 'fake_model_for_test_xyz'", res.stdout)


class TestChatCompleter(unittest.TestCase):
    def test_complete_filepath_relative(self):
        matches = complete_filepath("test_")
        self.assertIn("test_ollama_cli.py", matches)

    def test_complete_filepath_dot_slash(self):
        matches = complete_filepath("./")
        self.assertTrue(any("test_ollama_cli.py" in m for m in matches))

    def test_complete_filepath_nonexistent(self):
        matches = complete_filepath("/nonexistent_path_xyz_123/")
        self.assertEqual(matches, [])

    def test_make_chat_completer_slash_commands(self):
        completer = make_chat_completer(SLASH_COMMANDS, ["llama3:latest", "phi3:mini"])
        with patch("readline.get_line_buffer", return_value="/mo"):
            self.assertEqual(completer("/mo", 0), "/model")

    def test_make_chat_completer_models(self):
        completer = make_chat_completer(SLASH_COMMANDS, ["llama3:latest", "smollm2:135m"])
        with patch("readline.get_line_buffer", return_value="/model sm"):
            self.assertEqual(completer("sm", 0), "smollm2:135m")

    def test_make_chat_completer_file(self):
        completer = make_chat_completer(SLASH_COMMANDS, ["llama3:latest"])
        with patch("readline.get_line_buffer", return_value="/file test_"):
            res = completer("test_", 0)
            self.assertEqual(res, "test_ollama_cli.py")


class TestFileCommand(unittest.TestCase):
    def test_parse_file_command_args_simple(self):
        f, p = parse_file_command_args("README.md")
        self.assertEqual(f, "README.md")
        self.assertEqual(p, "")

    def test_parse_file_command_args_with_prompt(self):
        f, p = parse_file_command_args("README.md Review this document")
        self.assertEqual(f, "README.md")
        self.assertEqual(p, "Review this document")

    def test_parse_file_command_args_double_quotes(self):
        f, p = parse_file_command_args('"my file.py" Find all bugs')
        self.assertEqual(f, "my file.py")
        self.assertEqual(p, "Find all bugs")

    def test_load_file_for_chat_success(self):
        ok, content, path = load_file_for_chat("README.md Summarize key points")
        self.assertTrue(ok)
        self.assertIn("Summarize key points", content)
        self.assertIn("```markdown", content)
        self.assertIn("(Source: README.md)", content)

    def test_load_file_for_chat_not_found(self):
        ok, err, path = load_file_for_chat("nonexistent_test_file.xyz")
        self.assertFalse(ok)
        self.assertIn("File not found", err)

    def test_load_file_for_chat_directory(self):
        ok, err, path = load_file_for_chat(".")
        self.assertFalse(ok)
        self.assertIn("is a directory", err)

    def test_load_file_for_chat_empty(self):
        ok, err, path = load_file_for_chat("")
        self.assertFalse(ok)
        self.assertIn("Usage: /file", err)


class TestInteractiveChatInput(unittest.TestCase):
    def test_single_line_input(self):
        result = get_user_chat_input(input_func=lambda p: "Hello Ollama")
        self.assertEqual(result, "Hello Ollama")

    def test_backslash_continuation(self):
        inputs = ["First line \\", "Second line \\", "Third line"]
        result = get_user_chat_input(input_func=lambda p: inputs.pop(0))
        self.assertEqual(result, "First line\nSecond line\nThird line")

    def test_triple_quotes_multiline(self):
        inputs = ['"""def hello():', '    print("world")', '"""']
        result = get_user_chat_input(input_func=lambda p: inputs.pop(0))
        self.assertEqual(result, 'def hello():\n    print("world")')

    def test_triple_quotes_single_line(self):
        result = get_user_chat_input(input_func=lambda p: '"""single line block"""')
        self.assertEqual(result, "single line block")

    def test_triple_single_quotes(self):
        inputs = ["'''SELECT * FROM users;", "WHERE active = 1;'''"]
        result = get_user_chat_input(input_func=lambda p: inputs.pop(0))
        self.assertEqual(result, "SELECT * FROM users;\nWHERE active = 1;")

    def test_paste_mode(self):
        inputs = ["/paste", "line one", "line two", "/send"]
        result = get_user_chat_input(input_func=lambda p: inputs.pop(0))
        self.assertEqual(result, "line one\nline two")

    def test_paste_mode_cancel(self):
        inputs = ["/paste", "line one", "/cancel"]
        result = get_user_chat_input(input_func=lambda p: inputs.pop(0))
        self.assertEqual(result, "")

    def test_eof_handling(self):
        def raise_eof(p):
            raise EOFError
        result = get_user_chat_input(input_func=raise_eof)
        self.assertIsNone(result)

    def test_ctrl_c_single_cancels_line(self):
        def raise_sigint(p):
            raise KeyboardInterrupt
        result = get_user_chat_input(input_func=raise_sigint)
        self.assertEqual(result, "")


class TestRunModelHelpers(unittest.TestCase):
    def test_is_ip_or_host_ipv4(self):
        self.assertTrue(is_ip_or_host("127.0.0.1"))
        self.assertTrue(is_ip_or_host("192.168.1.1:11434"))
        self.assertTrue(is_ip_or_host("192.168.1.1:8080"))
        self.assertTrue(is_ip_or_host("192.168.1.1 8080"))
        self.assertTrue(is_ip_or_host("192.168.1.1,8080"))
        self.assertTrue(is_ip_or_host("192.168.1.1:8080/"))

    def test_is_ip_or_host_url(self):
        self.assertTrue(is_ip_or_host("http://127.0.0.1:11434"))
        self.assertTrue(is_ip_or_host("https://ollama.local:8443"))

    def test_is_ip_or_host_localhost(self):
        self.assertTrue(is_ip_or_host("localhost"))
        self.assertTrue(is_ip_or_host("localhost:8080"))

    def test_is_ip_or_host_model_names(self):
        self.assertFalse(is_ip_or_host("smollm2:135m"))
        self.assertFalse(is_ip_or_host("llama3:latest"))
        self.assertFalse(is_ip_or_host("deepseek-r1:1.5b"))
        self.assertFalse(is_ip_or_host("cieloforge/qwen2.5-14B:latest"))
        self.assertFalse(is_ip_or_host("llama3"))

    def test_make_chat_completer_run_command(self):
        completer = make_chat_completer(SLASH_COMMANDS, ["llama3:latest", "smollm2:135m"])
        with patch("readline.get_line_buffer", return_value="/run sm"):
            self.assertEqual(completer("sm", 0), "smollm2:135m")

    def test_pull_ollama_model_missing(self):
        ok, msg = pull_ollama_model("http://127.0.0.1:11434", "fake_nonexistent_model_xyz")
        self.assertFalse(ok)
        self.assertIn("file does not exist", msg.lower())


class TestInteractiveChatModelDownload(unittest.TestCase):
    def test_slash_commands_include_pull_and_download(self):
        self.assertIn("/pull", SLASH_COMMANDS)
        self.assertIn("/download", SLASH_COMMANDS)

    def test_chat_completer_pull_and_download(self):
        completer = make_chat_completer(SLASH_COMMANDS, ["llama3:latest", "smollm2:135m"])
        with patch("readline.get_line_buffer", return_value="/pu"):
            self.assertEqual(completer("/pu", 0), "/pull")
        with patch("readline.get_line_buffer", return_value="/down"):
            self.assertEqual(completer("/down", 0), "/download")
        with patch("readline.get_line_buffer", return_value="/pull sm"):
            self.assertEqual(completer("sm", 0), "smollm2:135m")
        with patch("readline.get_line_buffer", return_value="/download llam"):
            self.assertEqual(completer("llam", 0), "llama3:latest")

    def test_pull_ollama_model_sigint(self):
        def raise_sigint(*args, **kwargs):
            raise KeyboardInterrupt

        with patch("requests.post", side_effect=raise_sigint):
            ok, msg = pull_ollama_model("http://127.0.0.1:11434", "test-model")
            self.assertFalse(ok)
            self.assertIn("cancelled by user", msg)

    def test_interactive_select_model_pull_command(self):
        models = [{"name": "model-a:latest"}]
        with patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled new-model")) as mock_pull:
            with patch("builtins.input", return_value="pull new-model"):
                res = interactive_select_model(models, base_url="http://127.0.0.1:11434")
                self.assertEqual(res, "new-model")
                mock_pull.assert_called_once()

    def test_interactive_select_model_p_shortcut(self):
        models = [{"name": "model-a:latest"}]
        with patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled phi3")):
            with patch("builtins.input", side_effect=["p", "phi3"]):
                res = interactive_select_model(models, base_url="http://127.0.0.1:11434")
                self.assertEqual(res, "phi3")

    def test_interactive_select_model_unknown_confirm(self):
        models = [{"name": "model-a:latest"}]
        with patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled mistral")):
            with patch("builtins.input", side_effect=["mistral", "y"]):
                res = interactive_select_model(models, base_url="http://127.0.0.1:11434")
                self.assertEqual(res, "mistral")

    def test_interactive_chat_pull_command_switch(self):
        with patch("ollama_cli.check_ollama_tags", return_value={"models": [{"name": "smollm2:135m"}]}), \
             patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled mistral")) as mock_pull, \
             patch("ollama_cli.get_user_chat_input", side_effect=["/pull mistral", "/exit"]), \
             patch("builtins.input", side_effect=["y"]):
            rc = run_interactive_chat("127.0.0.1", initial_model="smollm2:135m")
            self.assertEqual(rc, 0)
            mock_pull.assert_called_once()
            self.assertEqual(mock_pull.call_args[0][1], "mistral")

    def test_interactive_chat_download_alias(self):
        with patch("ollama_cli.check_ollama_tags", return_value={"models": [{"name": "smollm2:135m"}]}), \
             patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled llama3.2")) as mock_pull, \
             patch("ollama_cli.get_user_chat_input", side_effect=["/download llama3.2", "/exit"]), \
             patch("builtins.input", side_effect=["y"]):
            rc = run_interactive_chat("127.0.0.1", initial_model="smollm2:135m")
            self.assertEqual(rc, 0)
            mock_pull.assert_called_once()
            self.assertEqual(mock_pull.call_args[0][1], "llama3.2")

    def test_interactive_chat_pull_no_arg_prompt(self):
        with patch("ollama_cli.check_ollama_tags", return_value={"models": [{"name": "smollm2:135m"}]}), \
             patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled gemma2:2b")) as mock_pull, \
             patch("ollama_cli.get_user_chat_input", side_effect=["/pull", "/exit"]), \
             patch("builtins.input", side_effect=["gemma2:2b", "y"]):
            rc = run_interactive_chat("127.0.0.1", initial_model="smollm2:135m")
            self.assertEqual(rc, 0)
            mock_pull.assert_called_once()
            self.assertEqual(mock_pull.call_args[0][1], "gemma2:2b")

    def test_interactive_chat_model_autopull(self):
        with patch("ollama_cli.check_ollama_tags", return_value={"models": [{"name": "smollm2:135m"}]}), \
             patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled qwen2.5:1.5b")) as mock_pull, \
             patch("ollama_cli.get_user_chat_input", side_effect=["/model qwen2.5:1.5b", "/exit"]), \
             patch("builtins.input", side_effect=["y"]):
            rc = run_interactive_chat("127.0.0.1", initial_model="smollm2:135m")
            self.assertEqual(rc, 0)
            mock_pull.assert_called_once()
            self.assertEqual(mock_pull.call_args[0][1], "qwen2.5:1.5b")

    def test_interactive_chat_404_recovery(self):
        with patch("ollama_cli.check_ollama_tags", return_value={"models": [{"name": "smollm2:135m"}]}), \
             patch("ollama_cli.stream_chat_turn", side_effect=RuntimeError("HTTP 404: model not found")), \
             patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled smollm2:135m")) as mock_pull, \
             patch("ollama_cli.get_user_chat_input", side_effect=["Hello model", "/exit"]), \
             patch("builtins.input", side_effect=["y"]):
            rc = run_interactive_chat("127.0.0.1", initial_model="smollm2:135m")
            self.assertEqual(rc, 0)
            mock_pull.assert_called_once()

    def test_interactive_chat_empty_registry_pull(self):
        with patch("ollama_cli.check_ollama_tags", side_effect=[
                 {"models": []},
                 {"models": [{"name": "smollm2:135m"}]},
                 {"models": [{"name": "smollm2:135m"}]},
             ]), \
             patch("ollama_cli.check_openai_models", return_value={"models": []}), \
             patch("ollama_cli.pull_ollama_model", return_value=(True, "Successfully pulled smollm2:135m")) as mock_pull, \
             patch("builtins.input", side_effect=["y"]), \
             patch("ollama_cli.get_user_chat_input", return_value="/exit"):
            rc = run_interactive_chat("127.0.0.1")
            self.assertEqual(rc, 0)
            mock_pull.assert_called_once()
            self.assertEqual(mock_pull.call_args[0][1], "smollm2:135m")


class TestMultiHostVerboseProgress(unittest.TestCase):
    def test_format_duration(self):
        self.assertEqual(format_duration(0), "00:00")
        self.assertEqual(format_duration(45), "00:45")
        self.assertEqual(format_duration(125), "02:05")
        self.assertEqual(format_duration(3661), "01:01:01")
        self.assertEqual(format_duration(-10), "00:00")

    def test_sliding_eta_basics(self):
        eta = SlidingETA(total_items=10, window_size=3)
        self.assertEqual(eta.remaining, 10)
        self.assertEqual(eta.format_eta(), "calculating...")

        eta.record_item(2.0)
        self.assertEqual(eta.remaining, 9)
        self.assertAlmostEqual(eta.sliding_rate, 2.0)
        self.assertEqual(eta.format_eta(), "00:18")

        eta.record_item(4.0)
        self.assertEqual(eta.remaining, 8)
        self.assertAlmostEqual(eta.sliding_rate, 3.0)
        self.assertEqual(eta.format_eta(), "00:24")

        eta.record_item(6.0)
        self.assertEqual(eta.remaining, 7)
        self.assertAlmostEqual(eta.sliding_rate, 4.0)
        self.assertEqual(eta.format_eta(), "00:28")

        # 4th item: window size is 3, so 2.0 is dropped -> [4.0, 6.0, 2.0] -> avg 4.0
        eta.record_item(2.0)
        self.assertEqual(eta.remaining, 6)
        self.assertAlmostEqual(eta.sliding_rate, 4.0)
        self.assertEqual(eta.format_eta(), "00:24")

        # Record remaining 6 items to complete
        for _ in range(6):
            eta.record_item(1.0)
        self.assertEqual(eta.remaining, 0)
        self.assertEqual(eta.format_eta(), "00:00")

    def test_format_target_status_brief(self):
        # Open with models
        rep1 = {
            "tags_api": {"success": True, "models": [{"name": "m1"}, {"name": "m2"}]},
            "chat_auth": {"summary_status": "OPEN"},
        }
        self.assertIn("OK (OPEN)", format_target_status_brief(rep1))
        self.assertIn("2 models", format_target_status_brief(rep1))

        # Open with speed test
        rep2 = {
            "tags_api": {"success": True, "models": [{"name": "m1"}]},
            "chat_auth": {"summary_status": "OPEN"},
            "chat_speed": {"success": True, "tokens_per_second": 28.4},
        }
        status2 = format_target_status_brief(rep2)
        self.assertIn("OK (OPEN)", status2)
        self.assertIn("28.4 tok/s", status2)

        # Unauthorized
        rep3 = {"tags_api": {"is_unauthorized": True, "status_code": 401}}
        self.assertIn("UNAUTHORIZED (HTTP 401)", format_target_status_brief(rep3))

        # Error / unreachable
        rep4 = {"error": "Connection refused", "tags_api": {"success": False}}
        self.assertIn("Connection refused", format_target_status_brief(rep4))

    def test_cli_multi_host_verbose_progress(self):
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/ollama_cli.py", "127.0.0.1", "127.0.0.1", "-v", "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Starting multi-host scan", res.stderr)
        self.assertIn("Processed IP: 127.0.0.1", res.stderr)
        self.assertIn("Slide ETA:", res.stderr)
        self.assertIn("Multi-host scan complete", res.stderr)
        # Verify stdout has the quiet output
        self.assertIn("127.0.0.1", res.stdout)


@unittest.skipUnless(HAS_DUCKDB, "DuckDB not installed")
class TestDuckDBIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_targets.duckdb")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_init_duckdb_and_tables(self):
        conn = init_duckdb(self.db_path)
        tables = [r[0] for r in conn.execute("SHOW TABLES").fetchall()]
        self.assertIn("targets", tables)
        self.assertIn("models", tables)
        conn.close()

    def test_save_and_get_cached_target(self):
        conn = init_duckdb(self.db_path)
        sample_report = {
            "target": "127.0.0.1",
            "base_url": "http://127.0.0.1:11434",
            "host": "127.0.0.1",
            "port": 11434,
            "version": "0.5.4",
            "tags_api": {
                "success": True,
                "latency_ms": 25.0,
                "models": [
                    {
                        "name": "llama3:latest",
                        "size": 4000000000,
                        "details": {"format": "gguf", "parameter_size": "8B", "quantization_level": "Q4_K_M"},
                    }
                ],
            },
            "openai_api": {"success": True, "latency_ms": 30.0},
            "chat_auth": {"is_authorized": True, "is_unauthorized": False, "summary_status": "OPEN"},
        }
        save_target_to_duckdb(conn, sample_report)

        # Retrieve exact target
        cached = get_cached_target(conn, "127.0.0.1")
        self.assertIsNotNone(cached)
        self.assertTrue(cached.get("_cached"))
        self.assertEqual(cached["target"], "127.0.0.1")
        self.assertEqual(cached["base_url"], "http://127.0.0.1:11434")

        # Retrieve with host:port format
        cached_port = get_cached_target(conn, "127.0.0.1:11434")
        self.assertIsNotNone(cached_port)
        self.assertEqual(cached_port["base_url"], "http://127.0.0.1:11434")

        # Check models table in DB
        models_rows = conn.execute("SELECT name, size_bytes FROM models WHERE host = '127.0.0.1'").fetchall()
        self.assertEqual(len(models_rows), 1)
        self.assertEqual(models_rows[0][0], "llama3:latest")
        conn.close()

    def test_save_and_get_cached_target_custom_port(self):
        conn = init_duckdb(self.db_path)
        sample_report = {
            "target": "10.0.0.99:8080",
            "base_url": "http://10.0.0.99:8080",
            "host": "10.0.0.99",
            "port": 8080,
            "version": "0.5.4",
            "tags_api": {"success": True, "models": []},
            "openai_api": {"success": True},
            "chat_auth": {"is_authorized": True, "is_unauthorized": False, "summary_status": "OPEN"},
        }
        save_target_to_duckdb(conn, sample_report)

        # Retrieve exact target
        cached = get_cached_target(conn, "10.0.0.99:8080")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["port"], 8080)
        self.assertEqual(cached["base_url"], "http://10.0.0.99:8080")

        # Verify DuckDB table stores 8080, not hardcoded 11434
        row = conn.execute("SELECT port, base_url FROM targets WHERE host = '10.0.0.99'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 8080)
        self.assertEqual(row[1], "http://10.0.0.99:8080")

        # Also test saving when port is None in report dict, but in target string
        fail_report = {
            "target": "10.0.0.100:9000",
            "error": "Connection refused",
        }
        save_target_to_duckdb(conn, fail_report)
        row_fail = conn.execute("SELECT port, base_url FROM targets WHERE host = '10.0.0.100'").fetchone()
        self.assertIsNotNone(row_fail)
        self.assertEqual(row_fail[0], 9000)
        self.assertEqual(row_fail[1], "http://10.0.0.100:9000")

        conn.close()

    def test_cli_db_single_host_cache_and_force(self):
        cli_path = "/home/chain/shod/ollama_cli.py"

        # 1. First probe: fresh network scan, saves to DB
        res1 = subprocess.run(
            [sys.executable, cli_path, "127.0.0.1", "-db", self.db_path, "-v", "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res1.returncode, 0)
        self.assertIn(f"DuckDB persistence enabled: {self.db_path}", res1.stderr)
        self.assertIn("saved to DuckDB", res1.stderr)

        # 2. Second probe: hits cache, no network scan
        res2 = subprocess.run(
            [sys.executable, cli_path, "127.0.0.1", "-db", self.db_path, "-v", "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res2.returncode, 0)
        self.assertIn("loaded from DuckDB cache", res2.stderr)

        # 3. Third probe with --force: re-probes and updates DB
        res3 = subprocess.run(
            [sys.executable, cli_path, "127.0.0.1", "-db", self.db_path, "--force", "-v", "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res3.returncode, 0)
        self.assertIn("re-probed (--force) and updated in DuckDB", res3.stderr)

    def test_cli_db_file_and_force(self):
        cli_path = "/home/chain/shod/ollama_cli.py"
        file_path = os.path.join(self.temp_dir.name, "targets.txt")
        with open(file_path, "w") as f:
            f.write("127.0.0.1\n127.0.0.1:11434\n")

        # 1. Multi-host from file
        res1 = subprocess.run(
            [sys.executable, cli_path, "-f", file_path, "-db", self.db_path, "-v", "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res1.returncode, 0)
        self.assertIn(f"DuckDB: {self.db_path}", res1.stderr)

        # 2. Second run: both should be cached
        res2 = subprocess.run(
            [sys.executable, cli_path, "-f", file_path, "-db", self.db_path, "-v", "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res2.returncode, 0)
        self.assertIn("[cached in DB]", res2.stderr)

        # 3. Third run with --force: re-probes both
        res3 = subprocess.run(
            [sys.executable, cli_path, "-f", file_path, "-db", self.db_path, "--force", "-v", "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res3.returncode, 0)
        self.assertIn("(force)", res3.stderr)

    def test_cli_db_summary_and_query(self):
        cli_path = "/home/chain/shod/ollama_cli.py"
        # Seed DB with a target
        subprocess.run(
            [sys.executable, cli_path, "127.0.0.1", "-db", self.db_path, "--quiet"],
            capture_output=True,
            text=True,
            timeout=20,
        )

        # DB summary
        res_sum = subprocess.run(
            [sys.executable, cli_path, "-db", self.db_path, "--db-summary"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_sum.returncode, 0)
        self.assertIn("Total Scanned Targets", res_sum.stdout)

        # DB query plain / table
        res_q = subprocess.run(
            [sys.executable, cli_path, "-db", self.db_path, "--db-query", "SELECT target, host, port FROM targets"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_q.returncode, 0)
        self.assertIn("127.0.0.1", res_q.stdout)

        # DB query JSON
        res_json = subprocess.run(
            [sys.executable, cli_path, "-db", self.db_path, "--db-query", "SELECT target, host FROM targets", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_json.returncode, 0)
        q_data = json.loads(res_json.stdout)
        self.assertIsInstance(q_data, list)
        self.assertEqual(len(q_data), 1)
        self.assertEqual(q_data[0]["target"], "127.0.0.1")



class TestIpRangeParsing(unittest.TestCase):
    def test_is_ip_range_valid(self):
        self.assertTrue(is_ip_range("192.168.1.0/24"))
        self.assertTrue(is_ip_range("10.0.0.0/16"))
        self.assertTrue(is_ip_range("127.0.0.1/30"))
        self.assertTrue(is_ip_range("192.168.1.1-192.168.1.50"))
        self.assertTrue(is_ip_range("192.168.1.1-50"))
        self.assertTrue(is_ip_range("192.168.1.*"))
        self.assertTrue(is_ip_range("192.168.1.0/30:11434"))
        self.assertTrue(is_ip_range("192.168.1.1-10:8080"))
        self.assertTrue(is_ip_range("http://192.168.1.0/30:11434"))
        self.assertTrue(is_ip_range("https://192.168.1.1-5"))
        self.assertTrue(is_ip_range("192.168.1.1-2, 192.168.2.1-2"))

    def test_is_ip_range_invalid(self):
        self.assertFalse(is_ip_range(""))
        self.assertFalse(is_ip_range("127.0.0.1"))
        self.assertFalse(is_ip_range("127.0.0.1:11434"))
        self.assertFalse(is_ip_range("localhost"))
        self.assertFalse(is_ip_range("example.com"))
        self.assertFalse(is_ip_range("not-a-range"))
        self.assertFalse(is_ip_range("192.168.1.1-999"))

    def test_is_ip_or_host_with_range(self):
        self.assertTrue(is_ip_or_host("192.168.1.0/24"))
        self.assertTrue(is_ip_or_host("192.168.1.1-50"))
        self.assertTrue(is_ip_or_host("192.168.1.*"))

    def test_parse_ip_range_cidr(self):
        res = parse_ip_range("192.168.1.0/30")
        self.assertEqual(res, ["192.168.1.1", "192.168.1.2"])

        res31 = parse_ip_range("192.168.1.0/31")
        self.assertEqual(res31, ["192.168.1.0", "192.168.1.1"])

        res32 = parse_ip_range("127.0.0.1/32")
        self.assertEqual(res32, ["127.0.0.1"])

        res_port = parse_ip_range("192.168.1.0/30:11434")
        self.assertEqual(res_port, ["192.168.1.1:11434", "192.168.1.2:11434"])

        res_scheme = parse_ip_range("http://192.168.1.0/30:11434")
        self.assertEqual(res_scheme, ["http://192.168.1.1:11434", "http://192.168.1.2:11434"])

    def test_parse_ip_range_dash(self):
        res_full = parse_ip_range("192.168.1.1-192.168.1.4")
        self.assertEqual(res_full, ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"])

        res_short = parse_ip_range("192.168.1.1-4")
        self.assertEqual(res_short, ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"])

        res_rev = parse_ip_range("192.168.1.4-1")
        self.assertEqual(res_rev, ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"])

        res_port = parse_ip_range("10.0.0.1-3:8080")
        self.assertEqual(res_port, ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"])

    def test_parse_ip_range_wildcard(self):
        res = parse_ip_range("192.168.5.*")
        self.assertEqual(len(res), 254)
        self.assertEqual(res[0], "192.168.5.1")
        self.assertEqual(res[-1], "192.168.5.254")

    def test_parse_ip_range_comma(self):
        res = parse_ip_range("127.0.0.1-2, 127.0.0.5-6")
        self.assertEqual(res, ["127.0.0.1", "127.0.0.2", "127.0.0.5", "127.0.0.6"])

    def test_parse_ip_range_single_ip(self):
        res = parse_ip_range("127.0.0.1")
        self.assertEqual(res, ["127.0.0.1"])
        res_port = parse_ip_range("127.0.0.1:11434")
        self.assertEqual(res_port, ["127.0.0.1:11434"])

    def test_parse_ip_range_safety_limit(self):
        with self.assertRaises(ValueError) as ctx:
            parse_ip_range("10.0.0.0/8")
        self.assertIn("exceeds the safety limit", str(ctx.exception))

    def test_parse_ip_range_invalid(self):
        with self.assertRaises(ValueError):
            parse_ip_range("invalid-range-xyz")
        with self.assertRaises(ValueError):
            parse_ip_range("192.168.1.1-999")


class TestIpRangeCliIntegration(unittest.TestCase):
    def test_cli_range_cidr_single_host(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "--range", "127.0.0.1/32", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("127.0.0.1", res.stdout)
        self.assertIn("OK", res.stdout)

    def test_cli_range_dash_multi_host(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "-r", "127.0.0.1-2", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # 127.0.0.1 OK, 127.0.0.2 ERR -> exit code 1
        self.assertEqual(res.returncode, 1)
        self.assertIn("127.0.0.1", res.stdout)
        self.assertIn("127.0.0.2", res.stdout)

    def test_cli_range_openai_only(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "-r", "127.0.0.1/32", "-o", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("127.0.0.1", res.stdout)
        lines = [ln for ln in res.stdout.splitlines() if "127.0.0.1" in ln]
        self.assertTrue(len(lines) > 0)
        parts = lines[0].split()
        self.assertEqual(parts[1], "—")  # TAGS
        self.assertEqual(parts[2], "OK") # OPENAI (/v1/models)

    def test_cli_range_json(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "-r", "127.0.0.1/32", "-j"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("openai_api", data)
        self.assertTrue(data["openai_api"]["success"])
        self.assertEqual(data["openai_api"]["status_code"], 200)

    def test_cli_range_verbose_progress(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "-r", "127.0.0.1-2", "-v", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Starting multi-host scan for 2 targets", res.stderr)
        self.assertIn("Processed IP: 127.0.0.1", res.stderr)
        self.assertIn("Slide ETA:", res.stderr)
        self.assertIn("Multi-host scan complete", res.stderr)

    @unittest.skipUnless(HAS_DUCKDB, "DuckDB not installed")
    def test_cli_range_duckdb(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        temp_dir = tempfile.mkdtemp()
        temp_db = os.path.join(temp_dir, "test_cache.duckdb")
        try:
            # 1. First probe writes to DuckDB
            res1 = subprocess.run(
                [sys.executable, cli_path, "-r", "127.0.0.1/32", "-db", temp_db, "-q"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(res1.returncode, 0)

            # 2. Second probe loads from cache
            res2 = subprocess.run(
                [sys.executable, cli_path, "-r", "127.0.0.1/32", "-db", temp_db, "-v", "-q"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(res2.returncode, 0)
            self.assertIn("[cached in DB]", res2.stderr)

            # 3. Third probe with --force re-probes
            res3 = subprocess.run(
                [sys.executable, cli_path, "-r", "127.0.0.1/32", "-db", temp_db, "--force", "-v", "-q"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(res3.returncode, 0)
            self.assertIn("(force)", res3.stderr)
            self.assertNotIn("[cached in DB]", res3.stderr)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_cli_range_positional(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "127.0.0.1/32", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("127.0.0.1", res.stdout)

    def test_cli_range_threads(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "-r", "127.0.0.1-2", "-T", "2", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("127.0.0.1", res.stdout)
        self.assertIn("127.0.0.2", res.stdout)

    def test_cli_range_invalid_error(self):
        cli_path = os.path.join(os.path.dirname(__file__), "ollama_cli.py")
        res = subprocess.run(
            [sys.executable, cli_path, "-r", "999.999.999.999/24"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Error parsing IP range", res.stderr)


if __name__ == "__main__":
    unittest.main()



