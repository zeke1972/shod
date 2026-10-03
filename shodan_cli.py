#!/usr/bin/env python3
"""
Shodan Search & IP Harvester CLI with Web Login and API Support

A fast and lightweight CLI to authenticate to Shodan via web login
(username/password) or API key, search queries, cycle through result pages,
and save or stream the resulting IP addresses.

Authentication Options:
  1. Web Login (Username & Password):
     - Command-line: -u / --username <USER> -W / --password <PASS>
     - Environment: SHODAN_USERNAME and SHODAN_PASSWORD
     - Interactive prompt if username provided without password
     - Authenticates against https://account.shodan.io/login, preserves web session
       cookies, and automatically retrieves the account's API key if available.
  2. Direct API Key:
     - Command-line: -k / --api-key <KEY>
     - Environment: SHODAN_API_KEY

Search Modes:
  - Web Scraping (--web): Scrapes results directly via the authenticated web session
    (https://www.shodan.io/search?query=...&page=...).
  - API Mode (--api): Queries the official Shodan REST API (https://api.shodan.io).
  - Auto (default): Uses API if key is present; falls back to authenticated web scraping
    if API query credits are unavailable or if web login was used.
"""

import argparse
import getpass
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    requests = None  # type: ignore
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

SHODAN_API_BASE = "https://api.shodan.io"
SHODAN_WEB_BASE = "https://www.shodan.io"
SHODAN_ACCOUNT_BASE = "https://account.shodan.io"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


# ============================================================================
# Web Login & HTML Extraction
# ============================================================================

def extract_api_key_from_account_html(html: str) -> Optional[str]:
    """
    Search for a 32-character hex/alphanumeric Shodan API key within
    account overview HTML.
    """
    if not html:
        return None

    # Pattern 1: input or code with id/name containing api-key / api_key
    patterns = [
        r'id=[\"\'](?:api-key|apikey|api_key)[\"\'][^>]*value=[\"\']([a-zA-Z0-9]{32})[\"\']',
        r'name=[\"\'](?:api-key|apikey|api_key)[\"\'][^>]*value=[\"\']([a-zA-Z0-9]{32})[\"\']',
        r'value=[\"\']([a-zA-Z0-9]{32})[\"\'][^>]*id=[\"\'](?:api-key|apikey|api_key)[\"\']',
        r'<code[^>]*id=[\"\'](?:api-key|apikey|api_key)[\"\'][^>]*>\s*([a-zA-Z0-9]{32})\s*</code>',
        r'API\s+Key[^<]*</h4>\s*<p[^>]*>\s*<code[^>]*>\s*([a-zA-Z0-9]{32})\s*</code>',
        r'API\s+Key[^<]*</h3>\s*<p[^>]*>\s*<code[^>]*>\s*([a-zA-Z0-9]{32})\s*</code>',
        r'API\s+Key\s*</th>\s*<td>\s*<code[^>]*>\s*([a-zA-Z0-9]{32})\s*</code>',
        r'API\s+Key.*?<code>\s*([a-zA-Z0-9]{32})\s*</code>',
        r'API\s+Key.*?value=[\"\']([a-zA-Z0-9]{32})[\"\']',
        r'API\s+Key.*?>\s*([a-zA-Z0-9]{32})\s*<',
        r'<code>\s*([a-zA-Z0-9]{32})\s*</code>',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()
    return None


def extract_account_info_from_html(html: str) -> Dict[str, Any]:
    """Extract account overview metrics (plan, credits, username) from account HTML."""
    info: Dict[str, Any] = {}
    if not html:
        return info

    api_key = extract_api_key_from_account_html(html)
    if api_key:
        info["api_key"] = api_key

    # Username
    user_m = re.search(r'Username[:\s]*<strong>([^<]+)</strong>', html, re.IGNORECASE)
    if not user_m:
        user_m = re.search(r'class=[\"\']user-name[\"\'][^>]*>([^<]+)<', html, re.IGNORECASE)
    if user_m:
        info["username"] = user_m.group(1).strip()

    # Plan / Membership
    plan_m = re.search(r'(?:Account\s+Plan|Membership|Plan)[:\s]*<strong>([^<]+)</strong>', html, re.IGNORECASE)
    if not plan_m:
        plan_m = re.search(r'class=[\"\']plan-name[\"\'][^>]*>([^<]+)<', html, re.IGNORECASE)
    if plan_m:
        info["plan"] = plan_m.group(1).strip()

    # Query Credits
    qc_m = re.search(r'Query\s+Credits[:\s]*<strong>([0-9,]+)</strong>', html, re.IGNORECASE)
    if qc_m:
        info["query_credits"] = int(qc_m.group(1).replace(",", ""))

    # Scan Credits
    sc_m = re.search(r'Scan\s+Credits[:\s]*<strong>([0-9,]+)</strong>', html, re.IGNORECASE)
    if sc_m:
        info["scan_credits"] = int(sc_m.group(1).replace(",", ""))

    return info


def login_shodan_web(
    username: str,
    password: str,
    session: Optional[Any] = None,
    base_url: str = SHODAN_ACCOUNT_BASE,
    timeout: float = 20.0,
) -> Tuple[bool, Any, str, Optional[str]]:
    """
    Authenticate against Shodan web login (https://account.shodan.io/login).
    Returns: (success: bool, session_obj: Any, error_msg: str, api_key: Optional[str])
    """
    if not username or not password:
        return False, None, "Username and password cannot be empty", None

    login_url = f"{base_url.rstrip('/')}/login"
    account_url = f"{base_url.rstrip('/')}"

    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    if HAS_REQUESTS and requests:
        if session is None:
            session = requests.Session()
        session.headers.update(headers)

        # Step 1: GET login page to retrieve session cookie and CSRF token
        try:
            get_resp = session.get(login_url, timeout=timeout)
        except Exception as e:
            return False, None, f"Failed to connect to Shodan login: {e}", None

        if get_resp.status_code in (403, 503) and ("cloudflare" in get_resp.text.lower() or "challenge" in get_resp.text.lower()):
            return False, None, "Cloudflare / Bot challenge encountered at login endpoint.", None

        if get_resp.status_code != 200:
            return False, None, f"Shodan login page returned HTTP {get_resp.status_code}", None

        # Extract CSRF token
        csrf_m = re.search(r'name=[\"\']csrf_token[\"\']\s+value=[\"\']([^\"\']+)[\"\']', get_resp.text)
        if not csrf_m:
            csrf_m = re.search(r'value=[\"\']([^\"\']+)[\"\']\s+name=[\"\']csrf_token[\"\']', get_resp.text)

        csrf_token = csrf_m.group(1) if csrf_m else ""

        # Step 2: POST credentials
        post_data = {
            "username": username.strip(),
            "password": password,
            "grant_type": "password",
            "continue": account_url,
        }
        if csrf_token:
            post_data["csrf_token"] = csrf_token

        post_headers = {
            "Referer": login_url,
            "Origin": base_url,
        }

        try:
            post_resp = session.post(
                login_url,
                data=post_data,
                headers=post_headers,
                allow_redirects=True,
                timeout=timeout,
            )
        except Exception as e:
            return False, None, f"Login POST failed: {e}", None

        # Step 3: Check for failure messages
        alert_m = re.search(
            r'<div class=[\"\']alert alert-error[\"\'][^>]*>(?:.*?<em>.*?</em>)?\s*(?:<p>)?(.*?)(?:</p>|</div>)',
            post_resp.text,
            re.DOTALL | re.IGNORECASE,
        )
        if alert_m:
            err_text = re.sub(r'<[^>]+>', '', alert_m.group(1)).strip()
            return False, None, err_text or "Invalid username or password", None

        if "Invalid username or password" in post_resp.text:
            return False, None, "Invalid username or password", None

        # If redirected back to login or status 401/403
        if post_resp.url.rstrip("/").endswith("/login") and post_resp.status_code == 200 and "password" in post_resp.text:
            return False, None, "Login failed (redirected back to login form)", None

        # Step 4: Login succeeded. Extract API key if available
        api_key = extract_api_key_from_account_html(post_resp.text)
        if not api_key:
            try:
                acct_resp = session.get(account_url, timeout=timeout)
                if acct_resp.status_code == 200:
                    api_key = extract_api_key_from_account_html(acct_resp.text)
            except Exception:
                pass

        return True, session, "", api_key

    else:
        # Standard library fallback using urllib & http.cookiejar
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

        req = urllib.request.Request(login_url, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as r:
                get_html = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as he:
            return False, None, f"HTTP {he.code} when loading login page", None
        except Exception as e:
            return False, None, f"Failed to connect to Shodan login: {e}", None

        csrf_m = re.search(r'name=[\"\']csrf_token[\"\']\s+value=[\"\']([^\"\']+)[\"\']', get_html)
        csrf_token = csrf_m.group(1) if csrf_m else ""

        post_data = {
            "username": username.strip(),
            "password": password,
            "grant_type": "password",
            "continue": account_url,
        }
        if csrf_token:
            post_data["csrf_token"] = csrf_token

        encoded_data = urllib.parse.urlencode(post_data).encode("utf-8")
        post_headers = dict(headers)
        post_headers["Referer"] = login_url
        post_headers["Content-Type"] = "application/x-www-form-urlencoded"

        post_req = urllib.request.Request(login_url, data=encoded_data, headers=post_headers)
        try:
            with opener.open(post_req, timeout=timeout) as r:
                post_html = r.read().decode("utf-8", errors="replace")
                final_url = r.geturl()
        except urllib.error.HTTPError as he:
            err_html = he.read().decode("utf-8", errors="replace")
            return False, None, f"HTTP {he.code}: {err_html[:200]}", None
        except Exception as e:
            return False, None, f"Login POST failed: {e}", None

        if "Invalid username or password" in post_html:
            return False, None, "Invalid username or password", None

        if final_url.rstrip("/").endswith("/login") and "password" in post_html:
            return False, None, "Login failed (redirected back to login form)", None

        api_key = extract_api_key_from_account_html(post_html)
        return True, opener, "", api_key


# ============================================================================
# Web Search & HTML Scraping
# ============================================================================

def search_shodan_web_page(
    query: str,
    session: Any,
    page: int = 1,
    base_url: str = SHODAN_WEB_BASE,
    timeout: float = 20.0,
    max_retries: int = 2,
) -> Tuple[bool, Dict[str, Any], str]:
    """
    Perform a search query via Shodan Web Search (https://www.shodan.io/search?query=...&page=...)
    using an authenticated session.
    Returns: (success: bool, data: Dict[str, Any], error_msg: str)
    """
    params = {"query": query, "page": str(page)}
    url = f"{base_url.rstrip('/')}/search?{urllib.parse.urlencode(params)}"
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Referer": f"{base_url.rstrip('/')}/",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    text = ""
    status_code = 200

    for attempt in range(max_retries + 1):
        try:
            if HAS_REQUESTS and isinstance(session, requests.Session):
                resp = session.get(url, headers=headers, timeout=timeout)
                status_code = resp.status_code
                text = resp.text
            elif hasattr(session, "open"):
                # urllib opener
                req = urllib.request.Request(url, headers=headers)
                try:
                    with session.open(req, timeout=timeout) as r:
                        status_code = r.status if hasattr(r, "status") else 200
                        text = r.read().decode("utf-8", errors="replace")
                except urllib.error.HTTPError as he:
                    status_code = he.code
                    text = he.read().decode("utf-8", errors="replace")
            else:
                return False, {}, "Unsupported session object type"

            if status_code == 429:
                if attempt < max_retries:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                return False, {}, "Shodan Web rate limit reached (HTTP 429 Too Many Requests)."

            if status_code in (403, 503) and ("cloudflare" in text.lower() or "challenge" in text.lower()):
                return False, {}, "Cloudflare / Bot challenge encountered during web search."

            if status_code != 200:
                return False, {}, f"Web search returned HTTP {status_code}"

            break

        except Exception as e:
            if attempt < max_retries:
                time.sleep(1.0)
                continue
            return False, {}, f"Network error during web search: {e}"

    # Check for authentication requirement alerts
    if "Please log in to use search filters" in text:
        return False, {}, "Authentication required: Please log in to use search filters."
    if "Please create a Shodan account and log in to access more results" in text:
        return False, {}, "Authentication required: Log in to access additional result pages."

    # Parse total results
    total = 0
    total_m = re.search(r'total-results[^>]*>\s*<h4[^>]*>([0-9,]+)', text, re.IGNORECASE)
    if not total_m:
        total_m = re.search(r'([0-9,]+)\s*</h4>\s*<h6>Top Countries', text, re.IGNORECASE)
    if not total_m:
        total_m = re.search(r'Total:\s*([0-9,]+)', text, re.IGNORECASE)

    if total_m:
        try:
            total = int(total_m.group(1).replace(",", ""))
        except ValueError:
            total = 0

    # Parse results from HTML blocks
    matches: List[Dict[str, Any]] = []

    # Check if query specified a port
    query_port_m = re.search(r'\bport:(\d+)\b', query, re.IGNORECASE)
    default_query_port = int(query_port_m.group(1)) if query_port_m else None

    # Split by result container
    blocks = re.split(r'<div\s+class=[\"\']result[\"\']>', text)
    if len(blocks) > 1:
        # First chunk is header, subsequent chunks are individual results
        for block in blocks[1:]:
            # Extract IP
            ip_m = re.search(r'href=[\"\']/host/([0-9a-fA-F:.]+)[\"\']', block)
            if not ip_m:
                ip_m = re.search(r'class=[\"\']hostnames[^\"\']*[\"\'][^>]*>\s*([0-9a-fA-F:.]+)', block)
            if not ip_m:
                continue

            ip = ip_m.group(1).strip()
            # Validate IP format (IPv4 or IPv6)
            if not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) or ":" in ip):
                continue

            # Extract port
            port = None
            port_m = re.search(r'href=[\"\']https?://' + re.escape(ip) + r':([0-9]+)[\"\']', block)
            if not port_m:
                port_m = re.search(r'href=[\"\']https?://[^/:]+:([0-9]+)[\"\']', block)
            if not port_m:
                port_m = re.search(r'class=[\"\']port[\"\'][^>]*>([0-9]+)<', block)

            if port_m:
                try:
                    port = int(port_m.group(1))
                except ValueError:
                    port = default_query_port
            else:
                port = default_query_port

            # Extract title / organization
            title_m = re.search(r'class=[\"\']title text-dark[\"\'][^>]*>([^<]+)<', block)
            title = title_m.group(1).strip() if title_m else ""

            hostnames: List[str] = []
            host_m = re.search(r'class=[\"\']hostnames[^\"\']*[\"\'][^>]*>([^<]+)<', block)
            if host_m and host_m.group(1).strip() != ip:
                hostnames.append(host_m.group(1).strip())

            matches.append({
                "ip_str": ip,
                "port": port,
                "title": title,
                "hostnames": hostnames,
            })
    else:
        # Fallback: scan for all /host/<ip> occurrences
        raw_ips = re.findall(r'href=[\"\']/host/([0-9a-fA-F:.]+)[\"\']', text)
        for ip in raw_ips:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) or ":" in ip:
                matches.append({
                    "ip_str": ip,
                    "port": default_query_port,
                    "title": "",
                    "hostnames": [],
                })

    if total == 0 and matches:
        total = len(matches)

    return True, {"total": total, "matches": matches}, ""


# ============================================================================
# API Endpoint Integration
# ============================================================================

def get_api_info(
    api_key: str,
    base_url: str = SHODAN_API_BASE,
    timeout: float = 10.0,
) -> Tuple[bool, Dict[str, Any], str]:
    """Query Shodan /api-info endpoint to check account plan and query credits."""
    url = f"{base_url.rstrip('/')}/api-info?key={urllib.parse.quote_plus(api_key.strip())}"
    headers = {"User-Agent": DEFAULT_USER_AGENT}

    try:
        if HAS_REQUESTS and requests:
            resp = requests.get(url, headers=headers, timeout=timeout)
            status_code = resp.status_code
            text = resp.text
        else:
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    status_code = r.status
                    text = r.read().decode("utf-8")
            except urllib.error.HTTPError as he:
                status_code = he.code
                text = he.read().decode("utf-8")

        if status_code == 401:
            return False, {}, "Invalid Shodan API key (HTTP 401 Unauthorized)"
        if status_code == 403:
            return False, {}, "Access forbidden (HTTP 403 Forbidden)"
        if status_code != 200:
            return False, {}, f"HTTP {status_code}: {text[:200]}"

        data = json.loads(text)
        if "error" in data:
            return False, {}, str(data["error"])
        return True, data, ""

    except Exception as e:
        return False, {}, str(e)


def search_shodan_page(
    query: str,
    api_key: str,
    page: int = 1,
    base_url: str = SHODAN_API_BASE,
    timeout: float = 20.0,
    max_retries: int = 2,
) -> Tuple[bool, Dict[str, Any], str]:
    """Fetch a single page of Shodan search results via REST API."""
    params = {
        "key": api_key.strip(),
        "query": query,
        "page": str(page),
    }
    url = f"{base_url.rstrip('/')}/shodan/host/search?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": DEFAULT_USER_AGENT}

    for attempt in range(max_retries + 1):
        try:
            if HAS_REQUESTS and requests:
                resp = requests.get(url, headers=headers, timeout=timeout)
                status_code = resp.status_code
                text = resp.text
            else:
                req = urllib.request.Request(url, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        status_code = r.status
                        text = r.read().decode("utf-8")
                except urllib.error.HTTPError as he:
                    status_code = he.code
                    text = he.read().decode("utf-8")

            if status_code == 401:
                return (
                    False,
                    {},
                    "Invalid Shodan API key (HTTP 401 Unauthorized). Check your key at https://account.shodan.io",
                )
            if status_code == 402 or "No query credits" in text:
                return (
                    False,
                    {},
                    "No Shodan query credits remaining (HTTP 402/403).",
                )
            if status_code == 429:
                if attempt < max_retries:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                return False, {}, "Shodan API rate limit exceeded (HTTP 429 Too Many Requests)."
            if status_code != 200:
                return False, {}, f"HTTP {status_code}: {text[:200]}"

            data = json.loads(text)
            if "error" in data:
                return False, {}, str(data["error"])
            return True, data, ""

        except Exception as e:
            if attempt < max_retries:
                time.sleep(1.0)
                continue
            return False, {}, f"Network error: {e}"

    return False, {}, "Max retries exceeded"


# ============================================================================
# Core Harvester Logic
# ============================================================================

def harvest_shodan_ips(
    query: str,
    session: Optional[Any] = None,
    api_key: Optional[str] = None,
    use_web: bool = False,
    start_page: int = 1,
    max_pages: int = 1,
    max_results: Optional[int] = None,
    with_port: bool = False,
    unique: bool = True,
    delay: float = 1.0,
    api_base_url: str = SHODAN_API_BASE,
    web_base_url: str = SHODAN_WEB_BASE,
    timeout: float = 20.0,
    verbose: bool = False,
) -> Tuple[List[str], Dict[str, Any]]:
    """
    Search Shodan and cycle through pages, extracting matching IP addresses.
    Supports authenticated web scraping and/or REST API queries with seamless fallback.
    Returns: (list_of_ips, summary_stats)
    """
    collected_ips: List[str] = []
    seen_ips: Set[str] = set()
    total_found = 0
    pages_queried = 0
    error_msg = ""
    active_engine = "web" if (use_web or not api_key) else "api"

    start = max(1, int(start_page))
    count = max(1, int(max_pages))
    end_page = start + count - 1

    for page in range(start, end_page + 1):
        pages_queried += 1
        ok = False
        data: Dict[str, Any] = {}
        err = ""

        # Attempt search based on active mode
        if active_engine == "api" and api_key:
            ok, data, err = search_shodan_page(
                query=query,
                api_key=api_key,
                page=page,
                base_url=api_base_url,
                timeout=timeout,
            )
            # If API search is unavailable (credits, 403 Cloudflare, rate limits) but we have a web session, fallback to web scraping!
            if not ok and session:
                if verbose:
                    print(f"[*] API search unavailable. Switching seamlessly to Web Search...")
                active_engine = "web"
                ok, data, err = search_shodan_web_page(
                    query=query,
                    session=session,
                    page=page,
                    base_url=web_base_url,
                    timeout=timeout,
                )

        elif session:
            ok, data, err = search_shodan_web_page(
                query=query,
                session=session,
                page=page,
                base_url=web_base_url,
                timeout=timeout,
            )
        else:
            ok = False
            err = "No valid authentication session or API key available."

        if not ok:
            error_msg = err
            break

        total_found = data.get("total", 0)
        matches = data.get("matches", [])
        if not matches:
            break

        page_ips = 0
        for m in matches:
            ip = m.get("ip_str")
            if not ip:
                continue
            port = m.get("port")
            entry = f"{ip}:{port}" if (with_port and port) else ip

            if unique:
                if entry not in seen_ips:
                    seen_ips.add(entry)
                    collected_ips.append(entry)
                    page_ips += 1
            else:
                collected_ips.append(entry)
                page_ips += 1

            if max_results and len(collected_ips) >= max_results:
                break

        if verbose:
            print(
                f"[*] [{active_engine.upper()}] Page {page}: extracted {page_ips} IPs "
                f"({len(collected_ips)} total collected, {total_found} available in Shodan)"
            )

        if max_results and len(collected_ips) >= max_results:
            break

        if total_found > 0 and len(collected_ips) >= total_found:
            break

        if page < end_page and delay > 0:
            time.sleep(delay)

    summary = {
        "query": query,
        "engine": active_engine,
        "total_available": total_found,
        "start_page": start,
        "pages_queried": pages_queried,
        "ips_collected": len(collected_ips),
        "error": error_msg,
    }
    return collected_ips, summary


# ============================================================================
# CLI Main Entrypoint
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="shodan_cli",
        description="Shodan Search & IP Harvester CLI with Web Login & API Pagination.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Web login with username & password (prompts for password securely):
  %(prog)s "port:11434 Ollama" -u myuser -o ips.txt

  # Pass password on command line or via env var:
  %(prog)s "port:11434" -u myuser -W mypass -p 3 -o ips.txt
  export SHODAN_USERNAME=myuser SHODAN_PASSWORD=mypass
  %(prog)s "product:Ollama" -p 2 -o ips.txt

  # Cycle through multiple pages and limit total results:
  %(prog)s "port:11434" -u myuser -p 5 --limit 100 -o targets.txt

  # Start scanning from page 3 and cycle 5 pages (pages 3 to 7):
  %(prog)s "port:11434" -u myuser -s 3 -p 5 -o targets.txt

  # Include port in saved output (IP:PORT):
  %(prog)s "port:11434" -u myuser -P -o targets.txt

  # Pipe directly into Ollama probe CLI:
  %(prog)s "port:11434" -u myuser --quiet | python3 ollama_cli.py -f -

  # Force web search scraping mode:
  %(prog)s "country:IT port:11434" -u myuser --web -o ips_it.txt

  # Check account information and remaining credits:
  %(prog)s --info -u myuser
  %(prog)s --info -k <API_KEY>
""",
    )

    parser.add_argument(
        "query",
        nargs="?",
        default=None,
        help="Shodan search query (e.g. 'port:11434 Ollama', 'product:OpenSSH', 'country:IT').",
    )

    # Authentication arguments
    auth_group = parser.add_argument_group("Authentication Options")
    auth_group.add_argument(
        "-u", "--user", "--username",
        type=str,
        dest="username",
        default=os.getenv("SHODAN_USERNAME"),
        help="Shodan web username or email (or set SHODAN_USERNAME env var).",
    )
    auth_group.add_argument(
        "-W", "--password",
        type=str,
        dest="password",
        default=os.getenv("SHODAN_PASSWORD"),
        help="Shodan web password (or set SHODAN_PASSWORD env var; prompts securely if omitted).",
    )
    auth_group.add_argument(
        "-k", "--api-key",
        type=str,
        dest="api_key",
        default=os.getenv("SHODAN_API_KEY"),
        help="Shodan API Key (or set SHODAN_API_KEY env var). Obtain from https://account.shodan.io.",
    )

    # Search & Pagination arguments
    search_group = parser.add_argument_group("Search & Pagination")
    search_group.add_argument(
        "-s", "--start-page", "--start",
        type=int,
        dest="start_page",
        default=1,
        help="Initial page number to start scanning from (default: 1).",
    )
    search_group.add_argument(
        "-p", "--pages",
        type=int,
        default=1,
        help="Number of result pages to cycle through (default: 1).",
    )
    search_group.add_argument(
        "-l", "--limit",
        type=int,
        default=None,
        help="Maximum total number of IPs to collect across pages.",
    )
    search_group.add_argument(
        "--web",
        action="store_true",
        dest="use_web",
        help="Force web scraping mode using authenticated session instead of REST API.",
    )
    search_group.add_argument(
        "--api",
        action="store_true",
        dest="force_api",
        help="Force official REST API mode (requires API key).",
    )
    search_group.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Polite delay in seconds between pagination requests (default: 1.0).",
    )

    # Output formatting arguments
    output_group = parser.add_argument_group("Output Formatting")
    output_group.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path to save harvested IPs (one per line, or '-' for stdout).",
    )
    output_group.add_argument(
        "-P", "--with-port",
        action="store_true",
        dest="with_port",
        help="Include port in the output format (e.g. '192.0.2.1:11434').",
    )
    output_group.add_argument(
        "--no-unique",
        action="store_true",
        dest="no_unique",
        help="Do not deduplicate IP entries across pages.",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: only output IP addresses without status banners or statistics.",
    )
    output_group.add_argument(
        "-j", "--json",
        action="store_true",
        dest="json_output",
        help="Output summary statistics and results in JSON format.",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed progress per page.",
    )

    # General & Diagnostics
    diag_group = parser.add_argument_group("Diagnostics & Network")
    diag_group.add_argument(
        "--info",
        action="store_true",
        help="Check Shodan account plan and remaining query credits, then exit.",
    )
    diag_group.add_argument(
        "-t", "--timeout",
        type=float,
        default=20.0,
        help="HTTP request timeout in seconds (default: 20.0).",
    )
    diag_group.add_argument(
        "--api-base-url",
        type=str,
        default=SHODAN_API_BASE,
        help=argparse.SUPPRESS,
    )
    diag_group.add_argument(
        "--web-base-url",
        type=str,
        default=SHODAN_WEB_BASE,
        help=argparse.SUPPRESS,
    )
    diag_group.add_argument(
        "--account-base-url",
        type=str,
        default=SHODAN_ACCOUNT_BASE,
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    session = None
    api_key = args.api_key
    username = args.username
    password = args.password

    # Prompt for password if username given without password
    if username and not password:
        if sys.stdin.isatty():
            try:
                entered_pass = getpass.getpass(f"Enter Shodan password for '{username}': ")
                if entered_pass:
                    password = entered_pass
            except (KeyboardInterrupt, EOFError):
                print("", file=sys.stderr)
                return 1
        else:
            print(
                f"[!] Error: Password required for user '{username}'. Pass via -W / --password or export SHODAN_PASSWORD.",
                file=sys.stderr,
            )
            return 1

    # Prompt if neither credentials nor API key provided
    if not username and not api_key:
        if sys.stdin.isatty():
            try:
                print("--- Shodan Authentication ---")
                entered_user = input("Shodan Username (leave empty to enter API Key): ").strip()
                if entered_user:
                    username = entered_user
                    entered_pass = getpass.getpass(f"Password for '{username}': ")
                    if entered_pass:
                        password = entered_pass
                else:
                    entered_key = input("Shodan API Key: ").strip()
                    if entered_key:
                        api_key = entered_key
            except (KeyboardInterrupt, EOFError):
                print("", file=sys.stderr)
                return 1

    # Validate authentication inputs
    if not username and not api_key:
        print("[!] Error: Shodan authentication is required.", file=sys.stderr)
        print("    Authenticate via web login: -u / --username <USER> [-W / --password <PASS>]", file=sys.stderr)
        print("    Or provide an API key:      -k / --api-key <KEY> or export SHODAN_API_KEY=<KEY>", file=sys.stderr)
        return 1

    # Perform web login if username provided
    if username and password:
        if not args.quiet and not args.json_output:
            print(f"[*] Authenticating to Shodan web as '{username}'...")

        login_ok, web_session, login_err, extracted_key = login_shodan_web(
            username=username,
            password=password,
            base_url=args.account_base_url,
            timeout=args.timeout,
        )

        if not login_ok:
            print(f"[!] Shodan Web Login Failed: {login_err}", file=sys.stderr)
            return 1

        session = web_session
        if not args.quiet and not args.json_output:
            print(f"[✔] Web login successful!")

        if extracted_key and not api_key:
            api_key = extracted_key
            if not args.quiet and not args.json_output:
                masked = f"{api_key[:6]}...{api_key[-4:]}"
                print(f"[*] Retrieved API Key from account: {masked}")

    # Handle --info request
    if args.info:
        info_data: Dict[str, Any] = {}

        if api_key:
            ok, data, err = get_api_info(api_key, base_url=args.api_base_url, timeout=args.timeout)
            if ok:
                info_data = data
            elif not session:
                print(f"[!] Shodan API Error: {err}", file=sys.stderr)
                return 1

        if session and (not info_data or "plan" not in info_data):
            try:
                acct_url = args.account_base_url.rstrip('/')
                if HAS_REQUESTS and isinstance(session, requests.Session):
                    r = session.get(acct_url, timeout=args.timeout)
                    scraped_info = extract_account_info_from_html(r.text)
                    info_data.update(scraped_info)
            except Exception:
                pass

        if args.json_output:
            print(json.dumps(info_data, indent=2))
            return 0

        plan = info_data.get("plan", "Free / Community")
        query_cred = info_data.get("query_credits", "N/A")
        scan_cred = info_data.get("scan_credits", "N/A")
        unlocked = info_data.get("unlocked_left", "N/A")

        print("\n" + "=" * 50)
        print(" Shodan Account Overview")
        print("=" * 50)
        if username:
            print(f" Username       : {username}")
        if api_key:
            masked = f"{api_key[:6]}...{api_key[-4:]}"
            print(f" API Key        : {masked}")
        print(f" Account Plan   : {plan}")
        print(f" Query Credits  : {query_cred}")
        print(f" Scan Credits   : {scan_cred}")
        print(f" Unlocked Left  : {unlocked}")
        print("=" * 50 + "\n")
        return 0

    if not args.query:
        parser.print_help()
        print(
            "\n[ERROR] No search query provided. Specify a query string (e.g. `shodan_cli.py \"port:11434 Ollama\"`).",
            file=sys.stderr,
        )
        return 1

    # Determine execution mode
    use_web = args.use_web
    if not use_web and not args.force_api and session:
        # Default to web search when authenticated via web login
        use_web = True
    elif args.force_api:
        use_web = False
        if not api_key:
            print("[!] Error: --api requires an API Key (-k / --api-key).", file=sys.stderr)
            return 1

    if not args.quiet and not args.json_output:
        mode_str = "Web Search Scraping" if (use_web or not api_key) else "Official REST API"
        start = max(1, args.start_page)
        pages = max(1, args.pages)
        if pages == 1:
            page_info = f"page {start}"
        else:
            page_info = f"pages {start} to {start + pages - 1}"
        print(f"[*] Querying Shodan via {mode_str} for: \"{args.query}\" ({page_info})...")

    ips, summary = harvest_shodan_ips(
        query=args.query,
        session=session,
        api_key=api_key,
        use_web=use_web,
        start_page=args.start_page,
        max_pages=args.pages,
        max_results=args.limit,
        with_port=args.with_port,
        unique=not args.no_unique,
        delay=args.delay,
        api_base_url=args.api_base_url,
        web_base_url=args.web_base_url,
        timeout=args.timeout,
        verbose=args.verbose or (not args.quiet and not args.json_output),
    )

    if summary.get("error"):
        if not args.quiet and not args.json_output:
            print(f"[!] Warning: {summary['error']}", file=sys.stderr)

    # Write output to file or stdout
    if args.output and args.output != "-":
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                for ip in ips:
                    f.write(f"{ip}\n")
            if not args.quiet and not args.json_output:
                print(f"[✔] Successfully saved {len(ips)} IPs to '{args.output}'.")
        except Exception as e:
            print(f"[!] Error writing to file '{args.output}': {e}", file=sys.stderr)
            return 1
    elif args.json_output:
        out = {
            "summary": summary,
            "ips": ips,
        }
        print(json.dumps(out, indent=2))
        return 0
    else:
        # Output directly to stdout
        for ip in ips:
            print(ip)

    if not args.quiet and not args.json_output and args.output and args.output != "-":
        engine_str = summary.get("engine", "web").upper()
        start = summary.get("start_page", 1)
        pages_q = summary.get("pages_queried", 1)
        if pages_q > 1:
            range_info = f"pages {start}-{start + pages_q - 1}"
        else:
            range_info = f"page {start}"
        print(
            f"[*] Summary [{engine_str}]: {summary['total_available']} total matches found | "
            f"{pages_q} pages queried ({range_info}) | {len(ips)} IPs extracted."
        )

    return 0 if (ips or not summary.get("error")) else 1


if __name__ == "__main__":
    sys.exit(main())
