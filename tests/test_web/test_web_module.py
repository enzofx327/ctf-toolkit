"""
Test suite for the Web Exploitation module.
Uses unittest.mock to avoid real network requests.
"""

import pytest
from unittest.mock import MagicMock, patch
from ctf_toolkit.modules.web.web_module import (
    WebModule,
    _parse_headers_arg,
    _load_wordlist,
    SQLI_ERROR_PATTERNS,
    XSS_PAYLOADS,
    TECH_SIGNATURES,
)


@pytest.fixture
def web():
    return WebModule()


def _make_response(status=200, text="", headers=None, url="http://test.com"):
    """Build a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.content = text.encode()
    resp.headers = headers or {}
    resp.url = url
    resp.reason = "OK"
    resp.history = []
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.1
    return resp


# ── Utility helpers ───────────────────────────────────────────────────────────

class TestParseHeaders:
    def test_single_header(self):
        result = _parse_headers_arg(["Authorization:Bearer token123"])
        assert result == {"Authorization": "Bearer token123"}

    def test_multiple_headers(self):
        result = _parse_headers_arg(["X-Custom:value", "Cookie:session=abc"])
        assert result["X-Custom"] == "value"
        assert result["Cookie"] == "session=abc"

    def test_none_input(self):
        result = _parse_headers_arg(None)
        assert result == {}

    def test_empty_list(self):
        result = _parse_headers_arg([])
        assert result == {}

    def test_header_without_colon(self):
        result = _parse_headers_arg(["NoColon"])
        assert result == {}


class TestLoadWordlist:
    def test_builtin_wordlist(self):
        words = _load_wordlist(None)
        assert len(words) > 0
        assert "admin" in words

    def test_missing_file_falls_back(self):
        words = _load_wordlist("/nonexistent/wordlist.txt")
        assert len(words) > 0  # Falls back to built-in

    def test_custom_wordlist(self, tmp_path):
        wl = tmp_path / "custom.txt"
        wl.write_text("alpha\nbeta\ngamma\n")
        words = _load_wordlist(str(wl))
        assert words == ["alpha", "beta", "gamma"]


# ── Module actions ────────────────────────────────────────────────────────────

class TestWebModuleScan:
    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_scan_success(self, mock_get, web):
        mock_get.return_value = _make_response(
            status=200,
            text="<html>Powered by WordPress wp-content login</html>",
            headers={
                "Server": "nginx",
                "X-Powered-By": "PHP/8.1",
                "Content-Type": "text/html",
            },
            url="http://target.com",
        )
        result = web.run("scan", url="http://target.com")
        assert result.success
        assert any("200" in f or "nginx" in f.lower() or "PHP" in f for f in result.findings)

    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_scan_connection_failed(self, mock_get, web):
        mock_get.return_value = None
        result = web.run("scan", url="http://unreachable.test")
        assert not result.success
        assert result.errors

    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_scan_detects_wordpress(self, mock_get, web):
        mock_get.return_value = _make_response(
            text="wp-content/themes/default wp-login.php",
            headers={},
        )
        result = web.run("scan", url="http://wp-site.test")
        assert result.success
        techs = result.data.get("technologies", [])
        assert "WordPress" in techs

    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_scan_missing_security_headers(self, mock_get, web):
        mock_get.return_value = _make_response(
            text="<html>test</html>",
            headers={"Content-Type": "text/html"},
        )
        result = web.run("scan", url="http://insecure.test")
        assert result.success
        missing = result.data.get("missing_security_headers", [])
        assert "Content-Security-Policy" in missing


class TestWebModuleSqli:
    def test_sqli_no_params(self, web):
        result = web.run("sqli", url="http://target.com/page")
        assert not result.success
        assert result.errors

    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_sqli_error_detection(self, mock_get, web):
        def side_effect(sess, url, **kwargs):
            if "'" in url:
                return _make_response(
                    text="You have an error in your SQL syntax near '''",
                    status=500,
                )
            return _make_response(text="Normal response", status=200)

        mock_get.side_effect = side_effect
        result = web.run("sqli", url="http://target.com/page?id=1")
        assert result.success
        assert result.data.get("findings_count", 0) > 0

    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_sqli_no_vuln_found(self, mock_get, web):
        mock_get.return_value = _make_response(
            text="Normal page content", status=200
        )
        result = web.run("sqli", url="http://target.com/page?id=1")
        assert result.success
        assert result.data.get("findings_count", 0) == 0


class TestWebModuleXss:
    def test_xss_no_params(self, web):
        result = web.run("xss", url="http://target.com/page")
        assert not result.success

    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_xss_reflected_detected(self, mock_get, web):
        def side_effect(sess, url, **kwargs):
            # Reflect any query string back into response
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            search_val = qs.get("q", [""])[0]
            return _make_response(text=f"<p>Search results for: {search_val}</p>")

        mock_get.side_effect = side_effect
        result = web.run("xss", url="http://target.com/search?q=test")
        assert result.success
        # At least one XSS payload should be reflected
        assert result.data.get("xss_findings", 0) > 0

    @patch("ctf_toolkit.modules.web.web_module._safe_get")
    def test_xss_no_reflection(self, mock_get, web):
        mock_get.return_value = _make_response(text="Safe page — no reflection")
        result = web.run("xss", url="http://target.com/page?input=test")
        assert result.success
        assert result.data.get("xss_findings", 0) == 0


class TestWebModuleRequest:
    @patch("requests.Session.request")
    def test_request_get(self, mock_request, web):
        mock_request.return_value = _make_response(
            status=200,
            text="<html>Hello</html>",
            headers={"Content-Type": "text/html", "Server": "nginx"},
        )
        result = web.run("request", url="http://target.com")
        assert result.success
        assert result.data.get("status_code") == 200

    @patch("requests.Session.request")
    def test_request_connection_error(self, mock_request, web):
        from requests.exceptions import ConnectionError
        mock_request.side_effect = ConnectionError("Connection refused")
        result = web.run("request", url="http://unreachable.test")
        assert not result.success


# ── Constants validation ──────────────────────────────────────────────────────

class TestConstants:
    def test_sqli_error_patterns_are_regex(self):
        import re
        for pattern in SQLI_ERROR_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None

    def test_xss_payloads_not_empty(self):
        assert len(XSS_PAYLOADS) >= 5
        for payload, name in XSS_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(name, str)

    def test_tech_signatures_not_empty(self):
        assert "WordPress" in TECH_SIGNATURES
        assert "PHP" in TECH_SIGNATURES
        assert len(TECH_SIGNATURES) >= 5
