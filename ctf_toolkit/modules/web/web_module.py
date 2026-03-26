"""
Web Exploitation Module for CTF Toolkit.

Provides:
  - Full target scan (headers, tech detection, common paths)
  - SQL injection detection (error-based, time-based)
  - Directory brute-forcing with threading
  - XSS detection
  - Custom HTTP request helper
"""

import re
import threading
import time
import queue
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, urlunparse, quote

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

from ctf_toolkit.core.base_module import BaseModule
from ctf_toolkit.core.plugin_system import module
from ctf_toolkit.core.config import config

console = Console()

# Suppress InsecureRequestWarning for CTF targets (often have self-signed certs)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────

DEFAULT_HEADERS = {
    "User-Agent": "CTF-Toolkit/1.0 (Security Research)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SQLI_PAYLOADS = [
    ("'", "error-based apostrophe"),
    ("''", "double apostrophe"),
    ("' OR '1'='1", "OR tautology"),
    ("' OR 1=1--", "comment bypass"),
    ("1' AND 1=2 UNION SELECT NULL--", "UNION probe"),
    ("1 AND SLEEP(2)--", "time-based SLEEP"),
    ("1 AND 1=1", "boolean true"),
    ("1 AND 1=2", "boolean false"),
    ("'; DROP TABLE users--", "stacked query probe"),
    ('" OR ""="', "double-quote variant"),
    ("1' ORDER BY 1--", "ORDER BY probe"),
    ("1' ORDER BY 100--", "ORDER BY large number"),
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"Warning.*mysql",
    r"sqlite.*error",
    r"syntax error.*unexpected",
    r"Unclosed quotation mark",
    r"unterminated quoted",
    r"Division by zero",
    r"SQLSTATE\[\d+\]",
    r"You have an error in your SQL syntax",
    r"pg_query\(\)",
    r"SQLiteException",
    r"DB2 SQL Error",
    r"microsoft.*odbc",
    r"jet database engine",
]

XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "basic script tag"),
    ("'\"><script>alert(1)</script>", "attribute break + script"),
    ("<img src=x onerror=alert(1)>", "img onerror"),
    ("<svg onload=alert(1)>", "svg onload"),
    ("javascript:alert(1)", "javascript protocol"),
    ("<body onload=alert(1)>", "body onload"),
    ("';alert(1)//", "inline JS break"),
    ("${alert(1)}", "template literal"),
    ("<iframe src=javascript:alert(1)>", "iframe javascript"),
    ("<details open ontoggle=alert(1)>", "details ontoggle"),
]

COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "admin/", "administrator/", "login/", "admin.php",
    "wp-admin/", "wp-login.php", "phpmyadmin/", "panel/",
    "dashboard/", "console/", "manager/", "config.php",
    "backup/", "backup.zip", "backup.sql", ".git/",
    ".svn/", ".env", "api/", "api/v1/", "swagger/",
    "docs/", "server-status", "server-info",
]

TECH_SIGNATURES: Dict[str, List[str]] = {
    "WordPress": ["wp-content", "wp-login", "wp-json"],
    "Drupal": ["Drupal.settings", "/sites/default/"],
    "Joomla": ["option=com_", "Joomla!"],
    "Laravel": ["laravel_session", "X-Powered-By: PHP"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Flask": ["Werkzeug", "flask"],
    "Express": ["X-Powered-By: Express"],
    "ASP.NET": ["ASP.NET_SessionId", "X-Powered-By: ASP.NET", "__VIEWSTATE"],
    "PHP": ["X-Powered-By: PHP", "PHPSESSID"],
    "Apache": ["Server: Apache"],
    "Nginx": ["Server: nginx"],
    "IIS": ["Server: Microsoft-IIS"],
}


# ──────────────────────────────────────────────────────────────────
# HTTP session factory
# ──────────────────────────────────────────────────────────────────

def _make_session(extra_headers: Optional[Dict] = None) -> requests.Session:
    sess = requests.Session()
    sess.headers.update(DEFAULT_HEADERS)
    if extra_headers:
        sess.headers.update(extra_headers)
    return sess


def _parse_headers_arg(headers: Optional[List[str]]) -> Dict[str, str]:
    """Parse ['Key:Value', ...] list into dict."""
    result = {}
    if not headers:
        return result
    for h in headers:
        if ":" in h:
            key, _, value = h.partition(":")
            result[key.strip()] = value.strip()
    return result


def _safe_get(
    session: requests.Session,
    url: str,
    timeout: int = 10,
    **kwargs,
) -> Optional[requests.Response]:
    try:
        return session.get(url, timeout=timeout, verify=False, allow_redirects=True, **kwargs)
    except (Timeout, ReqConnError, RequestException):
        return None


# ──────────────────────────────────────────────────────────────────
# Wordlist helpers
# ──────────────────────────────────────────────────────────────────

BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel", "config",
    "backup", "api", "test", "dev", "staging", "old", "new", "upload",
    "uploads", "files", "images", "assets", "static", "media", "js",
    "css", "includes", "lib", "library", "vendor", "node_modules",
    "phpinfo.php", "info.php", "index.php", "index.html", "index.htm",
    "home", "main", "default", "page", "pages", "contact", "about",
    "register", "signup", "logout", "profile", "account", "settings",
    "user", "users", "admin.php", "login.php", "register.php",
    "config.php", "database.php", "db.php", "wp-login.php",
    "phpmyadmin", "pma", "mysql", "sql", "database",
    "search", "query", "flag", "secret", "hidden", "private",
    ".git", ".svn", ".env", ".htaccess", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "README", "README.md", "CHANGELOG", "LICENSE",
    "shell.php", "webshell.php", "cmd.php", "exec.php",
    "ajax.php", "api.php", "rest.php", "service.php",
    "manager", "management", "maintenance", "install", "setup",
    "download", "downloads", "report", "reports", "logs", "log",
]


def _load_wordlist(wordlist_path: Optional[str]) -> List[str]:
    """Load wordlist from file or return built-in."""
    if wordlist_path:
        p = Path(wordlist_path)
        if p.exists():
            return [line.strip() for line in p.read_text().splitlines() if line.strip()]
    return BUILTIN_WORDLIST


# ──────────────────────────────────────────────────────────────────
# Main module
# ──────────────────────────────────────────────────────────────────

@module
class WebModule(BaseModule):
    """Web exploitation and enumeration utilities."""

    MODULE_NAME = "web"
    MODULE_DESCRIPTION = "HTTP scanning, SQLi/XSS detection, directory brute-force, request automation"

    def get_actions(self) -> List[str]:
        return ["scan", "sqli", "dir-brute", "xss", "request"]

    # ── Full scan ─────────────────────────────────────────────────────────
    def scan(
        self,
        url: str,
        headers: Optional[List[str]] = None,
        **_,
    ) -> None:
        """Comprehensive web target reconnaissance."""
        extra = _parse_headers_arg(headers)
        sess = _make_session(extra)
        timeout = int(config.get("web", "timeout", default=10))

        self.logger.info(f"Scanning target: {url}")
        self._result.add_finding(f"Target: {url}")

        # Initial request
        resp = _safe_get(sess, url, timeout=timeout)
        if resp is None:
            self._result.add_error(f"Could not connect to {url}")
            return

        self._result.add_finding(f"Status: HTTP {resp.status_code}")
        self._result.add_finding(f"Final URL: {resp.url}")

        # Response headers
        interesting_headers = [
            "Server", "X-Powered-By", "Content-Type", "Set-Cookie",
            "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
            "X-XSS-Protection", "Access-Control-Allow-Origin", "Location",
        ]
        for hdr in interesting_headers:
            if hdr in resp.headers:
                self._result.add_finding(f"Header [{hdr}]: {resp.headers[hdr]}")

        # Security header audit
        missing_security = []
        for hdr in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security",
                    "X-XSS-Protection"]:
            if hdr not in resp.headers:
                missing_security.append(hdr)
        if missing_security:
            self._result.add_finding(f"Missing security headers: {', '.join(missing_security)}")

        # Technology detection
        combined = (resp.text or "") + str(resp.headers)
        detected_tech = []
        for tech, signatures in TECH_SIGNATURES.items():
            if any(sig.lower() in combined.lower() for sig in signatures):
                detected_tech.append(tech)
        if detected_tech:
            self._result.add_finding(f"Detected technologies: {', '.join(detected_tech)}")

        # Common paths probe
        self._result.add_finding("Probing common paths...")
        found_paths = []
        for path in COMMON_PATHS:
            probe_url = url.rstrip("/") + "/" + path
            r = _safe_get(sess, probe_url, timeout=timeout)
            if r and r.status_code in (200, 301, 302, 403, 401):
                found_paths.append(f"[{r.status_code}] {probe_url}")

        for fp in found_paths:
            self._result.add_finding(fp)

        self._result.set_data("status_code", resp.status_code)
        self._result.set_data("technologies", detected_tech)
        self._result.set_data("found_paths", found_paths)
        self._result.set_data("missing_security_headers", missing_security)

    # ── SQL injection ──────────────────────────────────────────────────────
    def sqli(
        self,
        url: str,
        param: Optional[str] = None,
        method: str = "GET",
        **_,
    ) -> None:
        """SQL injection detection (error-based and time-based)."""
        sess = _make_session()
        timeout = int(config.get("web", "timeout", default=10))
        delay_threshold = float(config.get("web", "sqli_delay", default=0.5))

        # Parse URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params and not param:
            self._result.add_error(
                "No URL parameters found. Use ?param=value or --param name"
            )
            return

        test_params = [param] if param else list(params.keys())
        self._result.add_finding(f"Testing {len(test_params)} parameter(s): {', '.join(test_params)}")

        # Baseline response
        baseline = _safe_get(sess, url, timeout=timeout)
        baseline_len = len(baseline.text) if baseline else 0
        baseline_time = 0

        findings_count = 0
        for test_param in test_params:
            self._result.add_finding(f"\n--- Testing parameter: {test_param} ---")

            for payload, payload_name in SQLI_PAYLOADS:
                # Inject into parameter
                test_qs = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_qs[test_param] = payload
                injected_url = urlunparse(
                    parsed._replace(query=urlencode(test_qs))
                )

                start = time.monotonic()
                resp = _safe_get(sess, injected_url, timeout=timeout + 3)
                elapsed = time.monotonic() - start

                if resp is None:
                    continue

                response_body = resp.text.lower()

                # Error-based detection
                for error_pattern in SQLI_ERROR_PATTERNS:
                    if re.search(error_pattern, response_body, re.IGNORECASE):
                        self._result.add_finding(
                            f"[ERROR-BASED] '{payload_name}' → SQL error: "
                            f"matched pattern '{error_pattern}'"
                        )
                        findings_count += 1
                        break

                # Time-based detection (SLEEP/BENCHMARK)
                if "sleep" in payload.lower() and elapsed >= delay_threshold + 1:
                    self._result.add_finding(
                        f"[TIME-BASED] '{payload_name}' → response delayed "
                        f"{elapsed:.2f}s (threshold={delay_threshold + 1}s)"
                    )
                    findings_count += 1

                # Boolean-based: significant length difference
                len_diff = abs(len(resp.text) - baseline_len)
                if len_diff > 200 and "1=1" in payload:
                    self._result.add_finding(
                        f"[BOOLEAN] '{payload_name}' → response length differs "
                        f"by {len_diff} bytes"
                    )

        if findings_count == 0:
            self._result.add_finding("No obvious SQL injection found with tested payloads.")
            self._result.add_finding(
                "Try manual testing or a dedicated tool like sqlmap."
            )

        self._result.set_data("findings_count", findings_count)
        self._result.set_data("tested_params", test_params)
        self._result.set_data("payloads_tested", len(SQLI_PAYLOADS))

    # ── Directory brute-force ─────────────────────────────────────────────
    def dir_brute(
        self,
        url: str,
        wordlist: Optional[str] = None,
        threads: int = 10,
        extensions: Optional[List[str]] = None,
        **_,
    ) -> None:
        """Threaded directory and file brute-forcing."""
        if extensions is None:
            extensions = ["", ".php", ".html", ".txt"]

        words = _load_wordlist(wordlist)
        base_url = url.rstrip("/")
        timeout = int(config.get("web", "timeout", default=10))

        # Build full URL list
        targets = []
        for word in words:
            for ext in extensions:
                targets.append(f"{base_url}/{word}{ext}")

        self._result.add_finding(
            f"Brute-forcing {len(targets)} paths ({len(words)} words × {len(extensions)} extensions)"
        )
        self.logger.info(f"Starting dir-brute on {url} with {threads} threads")

        found: List[str] = []
        q: queue.Queue = queue.Queue()
        for t in targets:
            q.put(t)

        lock = threading.Lock()

        def worker():
            sess = _make_session()
            while True:
                try:
                    target_url = q.get_nowait()
                except queue.Empty:
                    break
                try:
                    resp = sess.get(
                        target_url,
                        timeout=timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    if resp.status_code not in (404, 400):
                        entry = f"[{resp.status_code}] {target_url}"
                        with lock:
                            found.append(entry)
                            console.print(f"  [green]{entry}[/]")
                except (Timeout, ReqConnError, RequestException):
                    pass
                finally:
                    q.task_done()

        thread_list = []
        for _ in range(min(threads, len(targets))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        if found:
            for f in found:
                self._result.add_finding(f)
        else:
            self._result.add_finding("No paths found.")

        self._result.set_data("found_count", len(found))
        self._result.set_data("paths_tested", len(targets))

    # ── XSS detection ────────────────────────────────────────────────────
    def xss(
        self,
        url: str,
        param: Optional[str] = None,
        **_,
    ) -> None:
        """Basic reflected XSS detection."""
        sess = _make_session()
        timeout = int(config.get("web", "timeout", default=10))

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params and not param:
            self._result.add_error("No URL parameters found.")
            return

        test_params = [param] if param else list(params.keys())
        findings_count = 0

        for test_param in test_params:
            self._result.add_finding(f"Testing XSS in parameter: {test_param}")
            for payload, payload_name in XSS_PAYLOADS:
                test_qs = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_qs[test_param] = payload
                injected_url = urlunparse(parsed._replace(query=urlencode(test_qs)))

                resp = _safe_get(sess, injected_url, timeout=timeout)
                if resp is None:
                    continue

                # Check if payload is reflected unescaped
                if payload in resp.text:
                    self._result.add_finding(
                        f"[REFLECTED XSS] '{payload_name}' reflected unescaped!\n"
                        f"  Payload: {payload}\n"
                        f"  URL: {injected_url}"
                    )
                    findings_count += 1
                # Partial reflection (common for filtered cases)
                elif any(part in resp.text for part in ["<script>", "onerror=", "onload=", "javascript:"]):
                    self._result.add_finding(
                        f"[PARTIAL] '{payload_name}' partially reflected – possible DOM XSS"
                    )

        if findings_count == 0:
            self._result.add_finding(
                "No reflected XSS found. Try DOM-based payloads or check JavaScript console."
            )

        self._result.set_data("xss_findings", findings_count)

    # ── HTTP request ──────────────────────────────────────────────────────
    def request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[List[str]] = None,
        follow: bool = False,
        **_,
    ) -> None:
        """Make a custom HTTP request and display the response."""
        extra = _parse_headers_arg(headers)
        sess = _make_session(extra)
        timeout = int(config.get("web", "timeout", default=10))

        # Parse POST data
        post_data = {}
        if data:
            for pair in data.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    post_data[k] = v

        try:
            resp = sess.request(
                method=method.upper(),
                url=url,
                data=post_data if post_data else None,
                timeout=timeout,
                verify=False,
                allow_redirects=follow,
            )
        except RequestException as e:
            self._result.add_error(f"Request failed: {e}")
            return

        self._result.add_finding(f"HTTP/{resp.status_code} {resp.reason}")
        self._result.add_finding(f"URL: {resp.url}")
        self._result.add_finding(f"Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
        self._result.add_finding(f"Content-Length: {len(resp.content)} bytes")

        if resp.history:
            for redir in resp.history:
                self._result.add_finding(f"Redirect: {redir.status_code} → {redir.headers.get('Location', '?')}")

        # Display response headers
        self._result.add_finding("--- Response Headers ---")
        for k, v in resp.headers.items():
            self._result.add_finding(f"  {k}: {v}")

        # Save response body
        out_file = self.save_raw(resp.text, f"response_{int(time.time())}.txt")

        # Preview body
        preview = resp.text[:500].replace("\n", " ")
        self._result.add_finding(f"--- Body Preview ---\n{preview}")

        self._result.set_data("status_code", resp.status_code)
        self._result.set_data("headers", dict(resp.headers))
        self._result.set_data("body_file", str(out_file))
        self._result.set_data("elapsed_ms", int(resp.elapsed.total_seconds() * 1000))
