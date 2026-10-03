#!/usr/bin/env python3
"""
Unit and integration tests for shodan_cli.py
Tests both Web Login/Scraping and REST API modes.
"""

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

from shodan_cli import (
    extract_account_info_from_html,
    extract_api_key_from_account_html,
    get_api_info,
    harvest_shodan_ips,
    login_shodan_web,
    search_shodan_page,
    search_shodan_web_page,
)


class MockShodanHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence HTTP server logs during test run
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        parsed = urllib.parse.parse_qs(body)

        if self.path.startswith("/login"):
            username = parsed.get("username", [""])[0]
            password = parsed.get("password", [""])[0]
            csrf_token = parsed.get("csrf_token", [""])[0]

            if username == "valid_user" and password == "valid_pass" and csrf_token == "csrf_test_token_123":
                self.send_response(200)
                self.send_header("Set-Cookie", "session=valid_session_cookie_123; Path=/")
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <html>
                <body>
                  <div class="container">
                    <h1>Account Overview</h1>
                    <p>Username: <strong>valid_user</strong></p>
                    <p>Account Plan: <strong>Member</strong></p>
                    <p>API Key: <code id="api-key">1234567890abcdef1234567890abcdef</code></p>
                    <p>Query Credits: <strong>100</strong></p>
                    <p>Scan Credits: <strong>50</strong></p>
                  </div>
                </body>
                </html>
                """)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <html>
                <body>
                  <div class="alert alert-error">
                    <em>Error:</em>
                    <p>Invalid username or password</p>
                  </div>
                </body>
                </html>
                """)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")

        if self.path.startswith("/login"):
            self.send_response(200)
            self.send_header("Set-Cookie", "session=initial_session_cookie; Path=/")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <body>
              <form action="/login" method="post">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="hidden" name="csrf_token" value="csrf_test_token_123" />
                <input type="submit" value="Login" />
              </form>
            </body>
            </html>
            """)

        elif self.path == "/" or self.path == "/account":
            if "session=valid_session_cookie_123" in cookie:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <html>
                <body>
                  <div class="container">
                    <h1>Account Overview</h1>
                    <p>Username: <strong>valid_user</strong></p>
                    <p>Account Plan: <strong>Member</strong></p>
                    <p>API Key: <code id="api-key">1234567890abcdef1234567890abcdef</code></p>
                    <p>Query Credits: <strong>100</strong></p>
                    <p>Scan Credits: <strong>50</strong></p>
                  </div>
                </body>
                </html>
                """)
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()

        elif self.path.startswith("/search"):
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            page = query_params.get("page", ["1"])[0]
            query = query_params.get("query", [""])[0]

            is_authenticated = "session=valid_session_cookie_123" in cookie

            if not is_authenticated and "port:" in query:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <html><body>
                  <div class="alert alert-error">
                    <p>Please log in to use search filters.</p>
                  </div>
                </body></html>
                """)
                return

            if not is_authenticated and page != "1":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <html><body>
                  <div class="alert alert-error">
                    <p>Please create a Shodan account and log in to access more results.</p>
                  </div>
                </body></html>
                """)
                return

            if page == "2":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <html><body>
                  <div class="total-results">
                    <h4>3</h4>
                  </div>
                  <div class="result">
                    <div class="heading">
                      <a href="/host/198.51.100.3" class="title text-dark">Ollama Node 3</a>
                      <a href="http://198.51.100.3:11434" class="text-danger"></a>
                    </div>
                  </div>
                </body></html>
                """)
            else:
                # Page 1
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <html><body>
                  <div class="total-results">
                    <h4>3</h4>
                    <h6>Top Countries</h6>
                  </div>
                  <div class="result">
                    <div class="heading">
                      <a href="/host/198.51.100.1" class="title text-dark">Ollama Node 1</a>
                      <a href="http://198.51.100.1:11434" class="text-danger"></a>
                    </div>
                    <div class="result-details">
                      <ul><li class="hostnames text-secondary">ollama1.test</li></ul>
                    </div>
                  </div>
                  <div class="result">
                    <div class="heading">
                      <a href="/host/198.51.100.2" class="title text-dark">Ollama Node 2</a>
                      <a href="http://198.51.100.2:11434" class="text-danger"></a>
                    </div>
                    <div class="result-details">
                      <ul><li class="hostnames text-secondary">ollama2.test</li></ul>
                    </div>
                  </div>
                  <!-- Duplicate entry on page 1 for deduplication test -->
                  <div class="result">
                    <div class="heading">
                      <a href="/host/198.51.100.1" class="title text-dark">Ollama Node 1</a>
                      <a href="http://198.51.100.1:11434" class="text-danger"></a>
                    </div>
                  </div>
                </body></html>
                """)

        elif self.path.startswith("/api-info"):
            if "INVALID_KEY" in self.path:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid API key"}).encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "plan": "developer",
                            "query_credits": 85,
                            "scan_credits": 100,
                            "unlocked_left": 100,
                        }
                    ).encode("utf-8")
                )

        elif self.path.startswith("/shodan/host/search"):
            if "INVALID_KEY" in self.path:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid API key"}).encode("utf-8"))

            elif "NO_CREDITS" in self.path:
                self.send_response(402)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No query credits left"}).encode("utf-8"))

            elif "page=2" in self.path:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "total": 3,
                            "matches": [
                                {
                                    "ip_str": "198.51.100.3",
                                    "port": 11434,
                                    "hostnames": ["ollama3.test"],
                                }
                            ],
                        }
                    ).encode("utf-8")
                )
            else:
                # Page 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "total": 3,
                            "matches": [
                                {
                                    "ip_str": "198.51.100.1",
                                    "port": 11434,
                                    "hostnames": ["ollama1.test"],
                                },
                                {
                                    "ip_str": "198.51.100.2",
                                    "port": 11434,
                                    "hostnames": ["ollama2.test"],
                                },
                                {
                                    "ip_str": "198.51.100.1",  # duplicate for testing
                                    "port": 11434,
                                    "hostnames": ["ollama1.test"],
                                },
                            ],
                        }
                    ).encode("utf-8")
                )
        else:
            self.send_response(404)
            self.end_headers()


class TestShodanWebAndAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockShodanHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # ------------------------------------------------------------------------
    # HTML Parsing & Key Extraction Tests
    # ------------------------------------------------------------------------

    def test_extract_api_key_from_account_html(self):
        html1 = '<code id="api-key">1234567890abcdef1234567890abcdef</code>'
        self.assertEqual(extract_api_key_from_account_html(html1), "1234567890abcdef1234567890abcdef")

        html2 = '<input name="api_key" value="abcdef1234567890abcdef1234567890">'
        self.assertEqual(extract_api_key_from_account_html(html2), "abcdef1234567890abcdef1234567890")

        html3 = '<p>No key here</p>'
        self.assertIsNone(extract_api_key_from_account_html(html3))

    def test_extract_account_info_from_html(self):
        sample = """
        <div class="container">
          <p>Username: <strong>testuser</strong></p>
          <p>Account Plan: <strong>Member</strong></p>
          <p>API Key: <code id="api-key">1234567890abcdef1234567890abcdef</code></p>
          <p>Query Credits: <strong>150</strong></p>
          <p>Scan Credits: <strong>75</strong></p>
        </div>
        """
        info = extract_account_info_from_html(sample)
        self.assertEqual(info.get("username"), "testuser")
        self.assertEqual(info.get("plan"), "Member")
        self.assertEqual(info.get("api_key"), "1234567890abcdef1234567890abcdef")
        self.assertEqual(info.get("query_credits"), 150)
        self.assertEqual(info.get("scan_credits"), 75)

    # ------------------------------------------------------------------------
    # Web Login Tests
    # ------------------------------------------------------------------------

    def test_login_shodan_web_success(self):
        ok, session, err, api_key = login_shodan_web(
            username="valid_user",
            password="valid_pass",
            base_url=self.base_url,
        )
        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.assertIsNotNone(session)
        self.assertEqual(api_key, "1234567890abcdef1234567890abcdef")

    def test_login_shodan_web_invalid_credentials(self):
        ok, session, err, api_key = login_shodan_web(
            username="invalid_user",
            password="wrong_password",
            base_url=self.base_url,
        )
        self.assertFalse(ok)
        self.assertIn("Invalid username or password", err)
        self.assertIsNone(api_key)

    def test_login_shodan_web_empty_credentials(self):
        ok, session, err, api_key = login_shodan_web(
            username="",
            password="",
            base_url=self.base_url,
        )
        self.assertFalse(ok)
        self.assertIn("cannot be empty", err)

    # ------------------------------------------------------------------------
    # Web Search Scraping Tests
    # ------------------------------------------------------------------------

    def test_search_shodan_web_page_authenticated(self):
        # First login to get an authenticated session
        ok, session, _, _ = login_shodan_web("valid_user", "valid_pass", base_url=self.base_url)
        self.assertTrue(ok)

        # Now search page 1
        s_ok, data, err = search_shodan_web_page(
            query="port:11434 Ollama",
            session=session,
            page=1,
            base_url=self.base_url,
        )
        self.assertTrue(s_ok)
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["matches"]), 3)
        self.assertEqual(data["matches"][0]["ip_str"], "198.51.100.1")
        self.assertEqual(data["matches"][0]["port"], 11434)

    def test_search_shodan_web_page_unauthenticated_filter_error(self):
        import requests
        unauth_session = requests.Session()

        s_ok, data, err = search_shodan_web_page(
            query="port:11434 Ollama",
            session=unauth_session,
            page=1,
            base_url=self.base_url,
        )
        self.assertFalse(s_ok)
        self.assertIn("Please log in to use search filters", err)

    def test_search_shodan_web_page_unauthenticated_page2_error(self):
        import requests
        unauth_session = requests.Session()

        s_ok, data, err = search_shodan_web_page(
            query="nginx",
            session=unauth_session,
            page=2,
            base_url=self.base_url,
        )
        self.assertFalse(s_ok)
        self.assertIn("Log in to access additional result pages", err)

    # ------------------------------------------------------------------------
    # Web Mode Harvester Tests (Pagination, Limits, Ports)
    # ------------------------------------------------------------------------

    def test_harvest_shodan_ips_web_mode_pagination_and_dedup(self):
        ok, session, _, _ = login_shodan_web("valid_user", "valid_pass", base_url=self.base_url)
        self.assertTrue(ok)

        ips, summary = harvest_shodan_ips(
            query="port:11434",
            session=session,
            use_web=True,
            max_pages=2,
            unique=True,
            web_base_url=self.base_url,
            delay=0,
        )
        self.assertEqual(len(ips), 3)
        self.assertIn("198.51.100.1", ips)
        self.assertIn("198.51.100.2", ips)
        self.assertIn("198.51.100.3", ips)
        self.assertEqual(summary["pages_queried"], 2)
        self.assertEqual(summary["engine"], "web")

    def test_harvest_shodan_ips_web_mode_with_port(self):
        ok, session, _, _ = login_shodan_web("valid_user", "valid_pass", base_url=self.base_url)
        self.assertTrue(ok)

        ips, summary = harvest_shodan_ips(
            query="port:11434",
            session=session,
            use_web=True,
            max_pages=1,
            with_port=True,
            unique=True,
            web_base_url=self.base_url,
            delay=0,
        )
        self.assertEqual(len(ips), 2)
        self.assertIn("198.51.100.1:11434", ips)
        self.assertIn("198.51.100.2:11434", ips)

    def test_harvest_shodan_ips_web_mode_limit(self):
        ok, session, _, _ = login_shodan_web("valid_user", "valid_pass", base_url=self.base_url)
        self.assertTrue(ok)

        ips, summary = harvest_shodan_ips(
            query="port:11434",
            session=session,
            use_web=True,
            max_pages=2,
            max_results=1,
            web_base_url=self.base_url,
            delay=0,
        )
        self.assertEqual(len(ips), 1)

    def test_harvest_shodan_ips_api_credits_fallback_to_web(self):
        ok, session, _, _ = login_shodan_web("valid_user", "valid_pass", base_url=self.base_url)
        self.assertTrue(ok)

        # Query with api_key="NO_CREDITS", which fails with HTTP 402 on API.
        # Should seamlessly fall back to web session!
        ips, summary = harvest_shodan_ips(
            query="port:11434",
            api_key="NO_CREDITS",
            session=session,
            use_web=False,
            max_pages=1,
            api_base_url=self.base_url,
            web_base_url=self.base_url,
            delay=0,
        )
        self.assertEqual(len(ips), 2)
        self.assertEqual(summary["engine"], "web")

    def test_harvest_shodan_ips_start_page(self):
        ok, session, _, _ = login_shodan_web("valid_user", "valid_pass", base_url=self.base_url)
        self.assertTrue(ok)

        # Start directly on page 2
        ips, summary = harvest_shodan_ips(
            query="port:11434",
            session=session,
            use_web=True,
            start_page=2,
            max_pages=1,
            unique=True,
            web_base_url=self.base_url,
            delay=0,
        )
        self.assertEqual(len(ips), 1)
        self.assertIn("198.51.100.3", ips)
        self.assertEqual(summary["start_page"], 2)
        self.assertEqual(summary["pages_queried"], 1)

    # ------------------------------------------------------------------------
    # REST API Core Tests
    # ------------------------------------------------------------------------

    def test_get_api_info_success(self):
        ok, data, err = get_api_info(api_key="VALID_KEY", base_url=self.base_url)
        self.assertTrue(ok)
        self.assertEqual(data["plan"], "developer")
        self.assertEqual(data["query_credits"], 85)

    def test_get_api_info_invalid_key(self):
        ok, data, err = get_api_info(api_key="INVALID_KEY", base_url=self.base_url)
        self.assertFalse(ok)
        self.assertIn("Invalid Shodan API key", err)

    def test_search_shodan_page_success(self):
        ok, data, err = search_shodan_page(
            query="port:11434",
            api_key="VALID_KEY",
            page=1,
            base_url=self.base_url,
        )
        self.assertTrue(ok)
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["matches"]), 3)

    def test_search_shodan_page_invalid_key(self):
        ok, data, err = search_shodan_page(
            query="port:11434",
            api_key="INVALID_KEY",
            page=1,
            base_url=self.base_url,
        )
        self.assertFalse(ok)
        self.assertIn("Invalid Shodan API key", err)


class TestShodanCliProcess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockShodanHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_cli_missing_auth_error(self):
        # Run without credentials and non-tty stdin
        res = subprocess.run(
            [sys.executable, "/home/chain/shod/shodan_cli.py", "port:11434"],
            input="",
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Shodan authentication is required", res.stderr)

    def test_cli_web_login_and_search_save_file(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
            output_file = tf.name

        try:
            cmd = [
                sys.executable,
                "/home/chain/shod/shodan_cli.py",
                "port:11434",
                "-u", "valid_user",
                "-W", "valid_pass",
                "-p", "2",
                "-P",  # with port
                "-o", output_file,
                "--web",
                "--account-base-url", self.base_url,
                "--web-base-url", self.base_url,
                "--delay", "0",
            ]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertEqual(res.returncode, 0, f"CLI stderr: {res.stderr}")
            self.assertIn("Web login successful", res.stdout)
            self.assertIn("Successfully saved 3 IPs", res.stdout)

            with open(output_file, "r", encoding="utf-8") as f:
                saved_content = f.read().splitlines()

            self.assertEqual(len(saved_content), 3)
            self.assertIn("198.51.100.1:11434", saved_content)
            self.assertIn("198.51.100.2:11434", saved_content)
            self.assertIn("198.51.100.3:11434", saved_content)
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_cli_quiet_pipe_output(self):
        cmd = [
            sys.executable,
            "/home/chain/shod/shodan_cli.py",
            "port:11434",
            "-u", "valid_user",
            "-W", "valid_pass",
            "-p", "1",
            "-q",  # quiet mode
            "--web",
            "--account-base-url", self.base_url,
            "--web-base-url", self.base_url,
            "--delay", "0",
        ]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(res.returncode, 0)
        lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertIn("198.51.100.1", lines)
        self.assertIn("198.51.100.2", lines)

    def test_cli_json_output(self):
        cmd = [
            sys.executable,
            "/home/chain/shod/shodan_cli.py",
            "port:11434",
            "-u", "valid_user",
            "-W", "valid_pass",
            "-p", "1",
            "-j",  # json mode
            "--web",
            "--account-base-url", self.base_url,
            "--web-base-url", self.base_url,
            "--delay", "0",
        ]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("summary", data)
        self.assertIn("ips", data)
        self.assertEqual(len(data["ips"]), 2)

    def test_cli_start_page(self):
        cmd = [
            sys.executable,
            "/home/chain/shod/shodan_cli.py",
            "port:11434",
            "-u", "valid_user",
            "-W", "valid_pass",
            "--start-page", "2",
            "-p", "1",
            "-q",
            "--web",
            "--account-base-url", self.base_url,
            "--web-base-url", self.base_url,
            "--delay", "0",
        ]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(res.returncode, 0)
        lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "198.51.100.3")


if __name__ == "__main__":
    unittest.main()

