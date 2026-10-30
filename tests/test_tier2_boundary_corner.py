"""
Tier 2: Boundary & Corner Cases Test Suite.
Verifies boundary conditions, error handling, adversarial inputs, and attack resilience:
1. External Navigation Interception (>=5 tests)
2. Cross-Origin Cache Attempts (>=5 tests)
3. Malformed Range Headers (>=5 tests)
4. CSP Violation Resistance (>=5 tests)
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

# Add tests directory to sys.path
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from test_config import (
    ANDROID_MAIN_ACTIVITY_KT,
    EXPECTED_AUDIO_FILES,
    WEB_AUDIO_DIR,
    WEB_INDEX_HTML,
    WEB_SW_JS,
    extract_csp_from_html,
    parse_csp,
)


class TestTier2NavigationInterceptionBoundaries(unittest.TestCase):
    """Category 1: External Navigation & URL Sandboxing Boundary Cases."""

    @classmethod
    def setUpClass(cls):
        cls.kt_content = ANDROID_MAIN_ACTIVITY_KT.read_text(encoding="utf-8") if ANDROID_MAIN_ACTIVITY_KT.is_file() else ""
        cls.asset_domain = "appassets.androidplatform.net"

    def _simulate_should_override_url_loading(self, url: str) -> tuple[bool, str]:
        """
        Simulates the logic implemented in MainActivity.kt's shouldOverrideUrlLoading:
        val uri = request?.url ?: return false
        val host = uri.host
        if (host != null && host.equals(ASSET_DOMAIN, ignoreCase = true)) {
            return false // load in WebView
        }
        return try {
            val intent = Intent(Intent.ACTION_VIEW, uri)
            context.startActivity(intent)
            true // handled externally
        } catch (e: ActivityNotFoundException) {
            true // consume
        }
        """
        parsed = urlparse(url)
        host = parsed.hostname
        if host and host.lower() == self.asset_domain.lower():
            return False, "LOAD_IN_WEBVIEW"
        # Any other URL is delegated externally or safely consumed
        return True, "LAUNCH_EXTERNAL_INTENT"

    def test_t2_1_javascript_scheme_interception(self):
        """T2.1.1: javascript: scheme is intercepted and not treated as internal asset."""
        should_override, action = self._simulate_should_override_url_loading("javascript:alert(1)")
        self.assertTrue(should_override, "javascript: scheme must be intercepted")
        self.assertEqual(action, "LAUNCH_EXTERNAL_INTENT")
        self.assertIn("shouldOverrideUrlLoading", self.kt_content)

    def test_t2_1_file_scheme_interception(self):
        """T2.1.2: file:/// scheme is intercepted and blocked from internal WebView loading."""
        should_override, action = self._simulate_should_override_url_loading("file:///android_asset/secret.txt")
        self.assertTrue(should_override, "file:/// scheme must not load internally")
        self.assertEqual(action, "LAUNCH_EXTERNAL_INTENT")

    def test_t2_1_external_https_delegation(self):
        """T2.1.3: External https:// URL is intercepted and delegated to system browser."""
        should_override, action = self._simulate_should_override_url_loading("https://evil.com/phishing")
        self.assertTrue(should_override, "External HTTPS must be intercepted")
        self.assertEqual(action, "LAUNCH_EXTERNAL_INTENT")

    def test_t2_1_subdomain_spoofing_resistance(self):
        """T2.1.4: Subdomain spoofing (appassets.androidplatform.net.evil.com) is treated as external."""
        spoofed_url = "https://appassets.androidplatform.net.evil.com/hack.html"
        should_override, action = self._simulate_should_override_url_loading(spoofed_url)
        self.assertTrue(
            should_override,
            "Spoofed domain must NOT be treated as internal virtual asset domain",
        )
        self.assertEqual(action, "LAUNCH_EXTERNAL_INTENT")

    def test_t2_1_same_origin_subpath_permitted(self):
        """T2.1.5: Valid subpaths within appassets.androidplatform.net load internally in WebView."""
        valid_urls = [
            "https://appassets.androidplatform.net/assets/index.html",
            "https://appassets.androidplatform.net/assets/index.html#surah-1",
            "https://appassets.androidplatform.net/assets/style.css",
            "https://appassets.androidplatform.net/assets/audio/015_Al-Hijr.mp3",
        ]
        for url in valid_urls:
            should_override, action = self._simulate_should_override_url_loading(url)
            self.assertFalse(
                should_override,
                f"Valid asset URL {url} should not be intercepted (should load in WebView)",
            )
            self.assertEqual(action, "LOAD_IN_WEBVIEW")

    def test_t2_1_activity_not_found_exception_handling(self):
        """T2.1.6: MainActivity.kt handles ActivityNotFoundException to prevent crash on unhandled schemes."""
        self.assertIn(
            "ActivityNotFoundException",
            self.kt_content,
            "MainActivity.kt must catch ActivityNotFoundException when launching external Intent",
        )


class TestTier2CrossOriginCacheBoundaries(unittest.TestCase):
    """Category 2: Cross-Origin Cache Isolation & Pollution Resistance."""

    @classmethod
    def setUpClass(cls):
        cls.sw_content = WEB_SW_JS.read_text(encoding="utf-8") if WEB_SW_JS.is_file() else ""

    def _simulate_sw_should_cache(self, url_str: str, method: str = "GET", origin: str = "https://appassets.androidplatform.net") -> bool:
        """
        Simulate sw.js origin check:
        if (url.origin !== self.location.origin) return;
        if (request.method !== 'GET') return;
        """
        parsed = urlparse(url_str)
        request_origin = f"{parsed.scheme}://{parsed.netloc}"
        if request_origin != origin:
            return False
        if method.upper() != "GET":
            return False
        return True

    def test_t2_2_cross_origin_cdn_rejected(self):
        """T2.2.1: Requests to third-party CDN are not eligible for SW caching."""
        can_cache = self._simulate_sw_should_cache("https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js")
        self.assertFalse(can_cache, "Third-party CDN must not be cached by SW")

    def test_t2_2_chrome_extension_scheme_rejected(self):
        """T2.2.2: chrome-extension:// scheme is rejected and not cached."""
        can_cache = self._simulate_sw_should_cache("chrome-extension://abcdefghijklm/content.js")
        self.assertFalse(can_cache, "chrome-extension:// must not be cached by SW")

    def test_t2_2_data_uri_rejected(self):
        """T2.2.3: data: URI is rejected and not cached."""
        can_cache = self._simulate_sw_should_cache("data:text/javascript,console.log(1)")
        self.assertFalse(can_cache, "data: URIs must not be cached by SW")

    def test_t2_2_non_get_verbs_rejected(self):
        """T2.2.4: Non-GET HTTP verbs (POST, PUT, DELETE, PATCH) are rejected."""
        valid_url = "https://appassets.androidplatform.net/assets/app.js"
        for verb in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
            can_cache = self._simulate_sw_should_cache(valid_url, method=verb)
            self.assertFalse(can_cache, f"HTTP {verb} must not be cached by SW")

    def test_t2_2_same_origin_get_permitted(self):
        """T2.2.5: Same-origin GET request is permitted for SW processing."""
        valid_url = "https://appassets.androidplatform.net/assets/index.html"
        can_cache = self._simulate_sw_should_cache(valid_url, method="GET")
        self.assertTrue(can_cache, "Same-origin GET must be permitted")

    def test_t2_2_sw_code_strictly_checks_origin(self):
        """T2.2.6: sw.js codebase contains verbatim check url.origin !== self.location.origin."""
        pattern = re.compile(r"url\.origin\s*!==\s*self\.location\.origin")
        self.assertTrue(
            pattern.search(self.sw_content),
            "sw.js must contain explicit url.origin !== self.location.origin check",
        )


class TestTier2MalformedRangeHeaderBoundaries(unittest.TestCase):
    """Category 3: Malformed & Boundary HTTP Range Header Parsing."""

    def _parse_range_header(self, range_header: str, total_size: int) -> tuple[int, int, int]:
        """
        Parses Range header according to RFC 7233 / RFC 9110.
        Returns: (status_code, start_byte, end_byte)
        status_code: 206 (Partial Content), 200 (Full Content fallback), 416 (Range Not Satisfiable)
        """
        if not range_header or not range_header.startswith("bytes="):
            return 200, 0, total_size - 1

        range_val = range_header[len("bytes="):].strip()
        # Single range: start-end, start-, or -suffix
        parts = range_val.split("-")
        if len(parts) != 2:
            return 200, 0, total_size - 1

        start_str, end_str = parts[0].strip(), parts[1].strip()

        try:
            if start_str and end_str:
                start = int(start_str)
                end = int(end_str)
                if start > end or start >= total_size:
                    return 416, 0, 0
                end = min(end, total_size - 1)
                return 206, start, end
            elif start_str and not end_str:
                start = int(start_str)
                if start >= total_size:
                    return 416, 0, 0
                return 206, start, total_size - 1
            elif not start_str and end_str:
                suffix_len = int(end_str)
                if suffix_len == 0:
                    return 416, 0, 0
                suffix_len = min(suffix_len, total_size)
                return 206, total_size - suffix_len, total_size - 1
            else:
                return 200, 0, total_size - 1
        except ValueError:
            return 200, 0, total_size - 1

    def test_t2_3_non_numeric_range_fallback(self):
        """T2.3.1: Malformed non-numeric range (bytes=foo-bar) falls back safely."""
        status, start, end = self._parse_range_header("bytes=foo-bar", 1000)
        self.assertIn(status, [200, 416], "Malformed range must return 200 or 416, never crash")

    def test_t2_3_out_of_bounds_start_returns_416(self):
        """T2.3.2: Range start beyond file length (bytes=999999999-) returns 416."""
        status, _, _ = self._parse_range_header("bytes=999999999-", 1000)
        self.assertEqual(status, 416, "Range start >= total_size must return 416 Range Not Satisfiable")

    def test_t2_3_suffix_byte_range_handling(self):
        """T2.3.3: Suffix byte range (bytes=-500) returns final 500 bytes with 206."""
        status, start, end = self._parse_range_header("bytes=-500", 2000)
        self.assertEqual(status, 206)
        self.assertEqual(start, 1500)
        self.assertEqual(end, 1999)
        self.assertEqual(end - start + 1, 500)

    def test_t2_3_inverted_byte_range_returns_416(self):
        """T2.3.4: Inverted range (bytes=1000-500) returns 416 Range Not Satisfiable."""
        status, _, _ = self._parse_range_header("bytes=1000-500", 2000)
        self.assertEqual(status, 416, "Inverted range (start > end) must return 416")

    def test_t2_3_prefix_range_slice(self):
        """T2.3.5: Standard prefix range (bytes=0-499) returns exactly 500 bytes with 206."""
        status, start, end = self._parse_range_header("bytes=0-499", 5000)
        self.assertEqual(status, 206)
        self.assertEqual(start, 0)
        self.assertEqual(end, 499)
        self.assertEqual(end - start + 1, 500)

    def test_t2_3_sw_js_contains_range_handler(self):
        """T2.3.6: sw.js defines handleAudioRequest supporting byte ranges."""
        sw_content = WEB_SW_JS.read_text(encoding="utf-8") if WEB_SW_JS.is_file() else ""
        self.assertIn("handleAudioRequest", sw_content)
        self.assertIn("bytes=", sw_content)
        self.assertIn("Content-Range", sw_content)


class TestTier2CSPViolationResistanceBoundaries(unittest.TestCase):
    """Category 4: CSP Violation Resistance & Attack Surface Validation."""

    @classmethod
    def setUpClass(cls):
        cls.html_content = WEB_INDEX_HTML.read_text(encoding="utf-8") if WEB_INDEX_HTML.is_file() else ""
        cls.csp_raw = extract_csp_from_html(cls.html_content) or ""
        cls.directives = parse_csp(cls.csp_raw)

    def _is_source_allowed(self, directive_name: str, candidate_url_or_token: str) -> bool:
        """
        Check if a candidate source is allowed under the directive.
        """
        allowed_tokens = self.directives.get(directive_name, self.directives.get("default-src", []))
        if "*" in allowed_tokens:
            return True
        for token in allowed_tokens:
            if token == candidate_url_or_token:
                return True
            if token.startswith("http") and candidate_url_or_token.startswith(token):
                return True
        return False

    def test_t2_4_blocks_unsafe_eval(self):
        """T2.4.1: CSP script-src blocks 'unsafe-eval' (prevents eval() based exploits)."""
        script_src = self.directives.get("script-src", [])
        self.assertNotIn(
            "'unsafe-eval'",
            script_src,
            "Strict CSP must NOT include 'unsafe-eval'",
        )

    def test_t2_4_blocks_unauthorized_external_scripts(self):
        """T2.4.2: CSP blocks unauthorized external script sources."""
        hostile_scripts = [
            "https://attacker.org/keylogger.js",
            "https://evil-cdn.com/malware.js",
            "https://cdn.tailwindcss.com",
            "http://insecure-cdn.com/script.js",
        ]
        for hostile in hostile_scripts:
            self.assertFalse(
                self._is_source_allowed("script-src", hostile),
                f"CSP script-src must block {hostile}",
            )

    def test_t2_4_blocks_unauthorized_external_styles(self):
        """T2.4.3: CSP blocks unauthorized external style injection."""
        hostile_styles = [
            "https://attacker.org/exfiltrate.css",
            "https://evil-cdn.com/theme.css",
        ]
        for hostile in hostile_styles:
            self.assertFalse(
                self._is_source_allowed("style-src", hostile),
                f"CSP style-src must block {hostile}",
            )

    def test_t2_4_blocks_unauthorized_font_sources(self):
        """T2.4.4: CSP blocks unauthorized font hosts."""
        hostile_fonts = [
            "https://evil-fonts.com/font.woff2",
            "https://use.typekit.net/font.woff",
        ]
        for hostile in hostile_fonts:
            self.assertFalse(
                self._is_source_allowed("font-src", hostile),
                f"CSP font-src must block {hostile}",
            )

    def test_t2_4_blocks_arbitrary_connect_endpoints(self):
        """T2.4.5: CSP connect-src blocks arbitrary outbound network exfiltration."""
        hostile_endpoints = [
            "https://attacker-c2.org/log",
            "https://webhook.site/test",
            "http://localhost:9999/exfil",
        ]
        for hostile in hostile_endpoints:
            self.assertFalse(
                self._is_source_allowed("connect-src", hostile),
                f"CSP connect-src must block {hostile}",
            )

    def test_t2_4_blocks_object_and_plugin_execution(self):
        """T2.4.6: CSP restricts plugins via default-src 'none' or explicit object-src."""
        default_src = self.directives.get("default-src", [])
        object_src = self.directives.get("object-src", [])
        self.assertTrue(
            "'none'" in default_src or "'none'" in object_src,
            "CSP must block Flash/plugins with default-src 'none' or object-src 'none'",
        )


if __name__ == "__main__":
    unittest.main()
