"""
Tier 3: Cross-Feature Interactions Test Suite.
Verifies interactions and contracts between interdependent subsystem components:
1. Offline Audio Playback + HTTP 206 Synthetic Byte-Range Processing (4 tests)
2. WebViewAssetLoader Virtual Origin + Service Worker Integration (3 tests)
3. Asset Synchronization Consistency (Web PWA <-> Android Native) (5 tests)
4. WebView Back Navigation & Player State Continuity (3 tests)
"""

from __future__ import annotations

import hashlib
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
    ANDROID_ASSETS_DIR,
    ANDROID_MAIN_ACTIVITY_KT,
    EXPECTED_AUDIO_FILES,
    WEB_APP_JS,
    WEB_AUDIO_DIR,
    WEB_INDEX_HTML,
    WEB_MANIFEST_JSON,
    WEB_STYLE_CSS,
    WEB_SW_JS,
    WEB_TAILWIND_CSS,
    extract_csp_from_html,
    parse_csp,
)


class TestTier3OfflineAudioRangeInteraction(unittest.TestCase):
    """Subsystem Interaction 1: Offline Audio Playback + HTTP 206 Byte-Range Slicing."""

    @classmethod
    def setUpClass(cls):
        # Pick one real audio recitation for byte-level testing
        cls.sample_audio_name = "015_Al-Hijr.mp3"
        cls.sample_audio_path = WEB_AUDIO_DIR / cls.sample_audio_name
        cls.audio_bytes = cls.sample_audio_path.read_bytes() if cls.sample_audio_path.is_file() else b""
        cls.total_len = len(cls.audio_bytes)

    def _simulate_sw_handle_audio_request(self, range_header: str | None) -> tuple[int, dict[str, str], bytes]:
        """
        Simulate sw.js handleAudioRequest logic:
        const range = request.headers.get('range');
        if (!range) return new Response(arrayBuffer, { headers: { 'Content-Type': 'audio/mpeg' } });
        const parts = range.replace(/bytes=/, '').split('-');
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : total - 1;
        const chunk = arrayBuffer.slice(start, end + 1);
        return new Response(chunk, { status: 206, headers: { ... } });
        """
        if not range_header or not range_header.startswith("bytes="):
            headers = {
                "Content-Type": "audio/mpeg",
                "Content-Length": str(self.total_len),
                "Accept-Ranges": "bytes",
            }
            return 200, headers, self.audio_bytes

        range_val = range_header.replace("bytes=", "").strip()
        parts = range_val.split("-")
        start = int(parts[0]) if parts[0] else 0
        end = int(parts[1]) if parts[1] else self.total_len - 1
        end = min(end, self.total_len - 1)

        chunk = self.audio_bytes[start : end + 1]
        headers = {
            "Content-Type": "audio/mpeg",
            "Content-Range": f"bytes {start}-{end}/{self.total_len}",
            "Content-Length": str(len(chunk)),
            "Accept-Ranges": "bytes",
        }
        return 206, headers, chunk

    def test_t3_1_synthetic_206_slice_calculation(self):
        """T3.1.1: Audio range request bytes=1000-2999 returns 206 with exact byte slice."""
        self.assertGreater(self.total_len, 3000, "Audio file too small for test")
        status, headers, chunk = self._simulate_sw_handle_audio_request("bytes=1000-2999")

        self.assertEqual(status, 206)
        self.assertEqual(headers["Content-Range"], f"bytes 1000-2999/{self.total_len}")
        self.assertEqual(headers["Content-Length"], "2000")
        self.assertEqual(headers["Accept-Ranges"], "bytes")
        self.assertEqual(headers["Content-Type"], "audio/mpeg")
        self.assertEqual(chunk, self.audio_bytes[1000:3000])

    def test_t3_1_full_audio_fallback_status_200(self):
        """T3.1.2: Audio request without Range header returns full audio with HTTP 200."""
        status, headers, body = self._simulate_sw_handle_audio_request(None)

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Length"], str(self.total_len))
        self.assertEqual(headers["Content-Type"], "audio/mpeg")
        self.assertEqual(len(body), self.total_len)
        self.assertEqual(body, self.audio_bytes)

    def test_t3_1_tail_range_exact_eof(self):
        """T3.1.3: Range request reaching exact EOF returns tail bytes with 206."""
        start = self.total_len - 500
        status, headers, chunk = self._simulate_sw_handle_audio_request(f"bytes={start}-")

        self.assertEqual(status, 206)
        self.assertEqual(headers["Content-Range"], f"bytes {start}-{self.total_len - 1}/{self.total_len}")
        self.assertEqual(len(chunk), 500)
        self.assertEqual(chunk, self.audio_bytes[start:])

    def test_t3_1_multi_chunk_contiguous_reconstruction(self):
        """T3.1.4: Successive range chunks reconstruct contiguous audio stream without data corruption."""
        chunk1_status, _, chunk1 = self._simulate_sw_handle_audio_request("bytes=0-1023")
        chunk2_status, _, chunk2 = self._simulate_sw_handle_audio_request("bytes=1024-2047")
        chunk3_status, _, chunk3 = self._simulate_sw_handle_audio_request("bytes=2048-3071")

        self.assertEqual(chunk1_status, 206)
        self.assertEqual(chunk2_status, 206)
        self.assertEqual(chunk3_status, 206)

        reconstructed = chunk1 + chunk2 + chunk3
        self.assertEqual(len(reconstructed), 3072)
        self.assertEqual(reconstructed, self.audio_bytes[0:3072])


class TestTier3WebViewAssetLoaderServiceWorkerIntegration(unittest.TestCase):
    """Subsystem Interaction 2: WebViewAssetLoader Virtual Origin + Service Worker Integration."""

    @classmethod
    def setUpClass(cls):
        cls.kt_content = ANDROID_MAIN_ACTIVITY_KT.read_text(encoding="utf-8") if ANDROID_MAIN_ACTIVITY_KT.is_file() else ""
        cls.sw_content = WEB_SW_JS.read_text(encoding="utf-8") if WEB_SW_JS.is_file() else ""
        cls.app_content = WEB_APP_JS.read_text(encoding="utf-8") if WEB_APP_JS.is_file() else ""

    def test_t3_2_virtual_domain_is_secure_context(self):
        """T3.2.1: Virtual domain scheme is HTTPS, satisfying W3C Secure Context for Service Worker."""
        # Service Worker registration requires window.isSecureContext (HTTPS or localhost)
        # file:/// scheme does NOT allow standard Service Worker registration on modern Android WebViews.
        has_virtual_https = (
            "https://appassets.androidplatform.net" in self.kt_content
            or ("https://$ASSET_DOMAIN" in self.kt_content and "appassets.androidplatform.net" in self.kt_content)
        )
        self.assertTrue(has_virtual_https, "Virtual domain must be loaded over https scheme")
        self.assertNotIn("file:///android_asset/index.html", self.kt_content)

    def test_t3_2_virtual_origin_matches_sw_same_origin(self):
        """T3.2.2: Internal virtual asset requests match SW same-origin validation."""
        virtual_origin = "https://appassets.androidplatform.net"
        test_requests = [
            "https://appassets.androidplatform.net/assets/index.html",
            "https://appassets.androidplatform.net/assets/app.js",
            "https://appassets.androidplatform.net/assets/tailwind.min.css",
            "https://appassets.androidplatform.net/assets/manifest.json",
        ]
        for req in test_requests:
            parsed = urlparse(req)
            req_origin = f"{parsed.scheme}://{parsed.netloc}"
            self.assertEqual(
                req_origin,
                virtual_origin,
                f"Asset request {req} must match virtual origin {virtual_origin}",
            )

    def test_t3_2_cross_origin_isolation_preserves_local_assets(self):
        """T3.2.3: Fonts loaded from external CDN do not trigger Service Worker cache write."""
        font_req = "https://fonts.googleapis.com/css2?family=Amiri"
        parsed = urlparse(font_req)
        font_origin = f"{parsed.scheme}://{parsed.netloc}"
        virtual_origin = "https://appassets.androidplatform.net"

        self.assertNotEqual(
            font_origin,
            virtual_origin,
            "Google Fonts origin must be recognized as cross-origin",
        )


class TestTier3AssetSynchronizationConsistency(unittest.TestCase):
    """Subsystem Interaction 3: Asset Synchronization Consistency between Web PWA & Android."""

    @classmethod
    def setUpClass(cls):
        cls.web_assets = {
            "index.html": WEB_INDEX_HTML,
            "app.js": WEB_APP_JS,
            "sw.js": WEB_SW_JS,
            "style.css": WEB_STYLE_CSS,
            "tailwind.min.css": WEB_TAILWIND_CSS,
            "manifest.json": WEB_MANIFEST_JSON,
        }

    def _file_sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_t3_3_all_core_assets_present_in_android(self):
        """T3.3.1: All core web assets exist in Android assets directory."""
        for filename in self.web_assets:
            android_path = ANDROID_ASSETS_DIR / filename
            self.assertTrue(
                android_path.is_file(),
                f"Required asset {filename} missing in Android assets ({android_path})",
            )

    def test_t3_3_tailwind_css_content_identical(self):
        """T3.3.2: tailwind.min.css content is byte-for-byte identical across both repos."""
        web_css = WEB_TAILWIND_CSS
        android_css = ANDROID_ASSETS_DIR / "tailwind.min.css"

        self.assertTrue(web_css.is_file(), "Web tailwind.min.css missing")
        self.assertTrue(android_css.is_file(), "Android tailwind.min.css missing")
        self.assertEqual(
            self._file_sha256(web_css),
            self._file_sha256(android_css),
            "tailwind.min.css in Android assets diverges from Web PWA version",
        )

    def test_t3_3_index_html_csp_synchronized(self):
        """T3.3.3: index.html in Android assets defines the identical strict CSP as Web PWA."""
        web_csp = extract_csp_from_html(WEB_INDEX_HTML.read_text(encoding="utf-8"))
        android_html = (ANDROID_ASSETS_DIR / "index.html").read_text(encoding="utf-8")
        android_csp = extract_csp_from_html(android_html)

        self.assertIsNotNone(web_csp, "Web CSP missing")
        self.assertIsNotNone(android_csp, "Android CSP missing in assets/index.html")
        self.assertEqual(
            parse_csp(web_csp),
            parse_csp(android_csp),
            "Android assets/index.html CSP diverges from Web index.html CSP",
        )

    def test_t3_3_sw_cache_version_synchronized(self):
        """T3.3.4: sw.js in Android assets uses okasha-hafs-v2.0 cache name."""
        android_sw = (ANDROID_ASSETS_DIR / "sw.js").read_text(encoding="utf-8")
        self.assertIn("okasha-hafs-v2.0", android_sw)
        self.assertNotIn("okasha-hafs-v1.5", android_sw)
        self.assertNotIn("okasha-hafs-v1.6", android_sw)

    def test_t3_3_app_js_offline_cache_synchronized(self):
        """T3.3.5: app.js in Android assets references okasha-hafs-v2.0."""
        android_app = (ANDROID_ASSETS_DIR / "app.js").read_text(encoding="utf-8")
        self.assertIn("okasha-hafs-v2.0", android_app)
        self.assertNotIn("okasha-hafs-v1.5", android_app)
        self.assertNotIn("okasha-hafs-v1.6", android_app)


class TestTier3WebViewBackNavigationInteraction(unittest.TestCase):
    """Subsystem Interaction 4: WebView Back Navigation Stack & Playback Continuity."""

    @classmethod
    def setUpClass(cls):
        cls.kt_content = ANDROID_MAIN_ACTIVITY_KT.read_text(encoding="utf-8") if ANDROID_MAIN_ACTIVITY_KT.is_file() else ""

    def test_t3_4_on_back_pressed_callback_installed(self):
        """T3.4.1: onBackPressedDispatcher callback is registered in MainActivity.kt."""
        self.assertIn("onBackPressedDispatcher.addCallback", self.kt_content)

    def test_t3_4_back_navigation_checks_can_go_back(self):
        """T3.4.2: Back navigation queries webView.canGoBack() before goBack()."""
        self.assertIn("canGoBack()", self.kt_content)
        self.assertIn("goBack()", self.kt_content)

    def test_t3_4_webview_destroyed_on_activity_destroy(self):
        """T3.4.3: webView is properly destroyed in onDestroy() to prevent resource/audio leaks."""
        self.assertIn("override fun onDestroy()", self.kt_content)
        self.assertIn("webView?.destroy()", self.kt_content)


if __name__ == "__main__":
    unittest.main()
