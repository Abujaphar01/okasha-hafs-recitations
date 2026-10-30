"""
Tier 1: Feature Coverage Test Suite.
Verifies foundational security and hardening requirements across Android and Web PWA:
1. Android Manifest (>=5 tests)
2. Android WebView Settings (>=5 tests)
3. AndroidX WebViewAssetLoader (>=5 tests)
4. Web Content Security Policy (>=5 tests)
5. Static Tailwind & Supply Chain (>=5 tests)
6. Service Worker Same-Origin Isolation (>=5 tests)
7. Cache Naming Synchronization (>=5 tests)
8. Repository Hygiene & Privacy (>=5 tests)
"""

from __future__ import annotations

import re
import unittest
import sys
from pathlib import Path

# Add tests directory to sys.path for standalone and runner execution
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from test_config import (
    ANDROID_ASSETS_DIR,
    ANDROID_BUILD_GRADLE_KTS,
    ANDROID_GITIGNORE,
    ANDROID_LIBS_VERSIONS_TOML,
    ANDROID_MAIN_ACTIVITY_KT,
    ANDROID_MANIFEST_XML,
    EXPECTED_AUDIO_FILES,
    WEB_APP_JS,
    WEB_AUDIO_DIR,
    WEB_GITIGNORE,
    WEB_INDEX_HTML,
    WEB_SW_JS,
    WEB_TAILWIND_CSS,
    extract_csp_from_html,
    parse_android_manifest,
    parse_csp,
)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class TestTier1AndroidManifest(unittest.TestCase):
    """Category 1: Android Manifest Security Configuration."""

    @classmethod
    def setUpClass(cls):
        cls.manifest_path = ANDROID_MANIFEST_XML
        cls.root = parse_android_manifest(cls.manifest_path)
        cls.app_elem = cls.root.find("application")

    def test_t1_1_manifest_exists(self):
        """T1.1.1: AndroidManifest.xml exists and is parseable."""
        self.assertTrue(self.manifest_path.is_file(), f"Missing {self.manifest_path}")
        self.assertIsNotNone(self.root, "AndroidManifest.xml root is None")

    def test_t1_1_cleartext_traffic_disabled(self):
        """T1.1.2: android:usesCleartextTraffic is false or not true."""
        self.assertIsNotNone(self.app_elem, "<application> element not found")
        attr_key = f"{{{ANDROID_NS}}}usesCleartextTraffic"
        uses_cleartext = self.app_elem.attrib.get(attr_key)
        self.assertIn(
            uses_cleartext,
            ["false", None],
            f"usesCleartextTraffic must be 'false' or omitted, found: {uses_cleartext}",
        )

    def test_t1_1_allow_backup_disabled(self):
        """T1.1.3: android:allowBackup is explicitly 'false'."""
        self.assertIsNotNone(self.app_elem, "<application> element not found")
        attr_key = f"{{{ANDROID_NS}}}allowBackup"
        allow_backup = self.app_elem.attrib.get(attr_key)
        self.assertEqual(
            allow_backup,
            "false",
            f"allowBackup must be explicitly 'false', found: {allow_backup}",
        )

    def test_t1_1_internet_permission_declared(self):
        """T1.1.4: android.permission.INTERNET is declared."""
        permissions = [
            elem.attrib.get(f"{{{ANDROID_NS}}}name")
            for elem in self.root.findall("uses-permission")
        ]
        self.assertIn(
            "android.permission.INTERNET",
            permissions,
            "android.permission.INTERNET is required for audio streaming",
        )

    def test_t1_1_foreground_service_permission_declared(self):
        """T1.1.5: Foreground service permissions are declared."""
        permissions = [
            elem.attrib.get(f"{{{ANDROID_NS}}}name")
            for elem in self.root.findall("uses-permission")
        ]
        self.assertTrue(
            "android.permission.FOREGROUND_SERVICE" in permissions
            or "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK" in permissions,
            "Foreground service media playback permission missing in AndroidManifest.xml",
        )

    def test_t1_1_launcher_activity_exported(self):
        """T1.1.6: Main launcher activity is exported and properly configured."""
        activities = self.app_elem.findall("activity")
        found_main = False
        for act in activities:
            name = act.attrib.get(f"{{{ANDROID_NS}}}name")
            if name in [".MainActivity", "com.example.okashahafs.MainActivity"]:
                found_main = True
                self.assertEqual(
                    act.attrib.get(f"{{{ANDROID_NS}}}exported"),
                    "true",
                    "MainActivity must be exported=true for launcher entrypoint",
                )
        self.assertTrue(found_main, "MainActivity declaration not found in AndroidManifest.xml")


class TestTier1WebViewSettings(unittest.TestCase):
    """Category 2: Android WebView Hardened Settings in MainActivity.kt."""

    @classmethod
    def setUpClass(cls):
        cls.kt_path = ANDROID_MAIN_ACTIVITY_KT
        cls.content = cls.kt_path.read_text(encoding="utf-8") if cls.kt_path.is_file() else ""

    def test_t1_2_main_activity_exists(self):
        """T1.2.1: MainActivity.kt file exists and is readable."""
        self.assertTrue(self.kt_path.is_file(), f"Missing {self.kt_path}")
        self.assertGreater(len(self.content), 0, "MainActivity.kt is empty")

    def test_t1_2_allow_file_access_disabled(self):
        """T1.2.2: allowFileAccess is explicitly set to false."""
        pattern = re.compile(r"allowFileAccess\s*=\s*false")
        self.assertTrue(
            pattern.search(self.content),
            "MainActivity.kt must explicitly set allowFileAccess = false",
        )

    def test_t1_2_allow_content_access_disabled(self):
        """T1.2.3: allowContentAccess is explicitly set to false."""
        pattern = re.compile(r"allowContentAccess\s*=\s*false")
        self.assertTrue(
            pattern.search(self.content),
            "MainActivity.kt must explicitly set allowContentAccess = false",
        )

    def test_t1_2_javascript_enabled(self):
        """T1.2.4: javaScriptEnabled is set to true for web player functionality."""
        pattern = re.compile(r"javaScriptEnabled\s*=\s*true")
        self.assertTrue(
            pattern.search(self.content),
            "MainActivity.kt must set javaScriptEnabled = true for PWA",
        )

    def test_t1_2_dom_storage_enabled(self):
        """T1.2.5: domStorageEnabled is set to true for web local storage."""
        pattern = re.compile(r"domStorageEnabled\s*=\s*true")
        self.assertTrue(
            pattern.search(self.content),
            "MainActivity.kt must set domStorageEnabled = true",
        )

    def test_t1_2_media_playback_requires_user_gesture_disabled(self):
        """T1.2.6: mediaPlaybackRequiresUserGesture is set to false."""
        pattern = re.compile(r"mediaPlaybackRequiresUserGesture\s*=\s*false")
        self.assertTrue(
            pattern.search(self.content),
            "MainActivity.kt must set mediaPlaybackRequiresUserGesture = false for auto-next track playback",
        )


class TestTier1WebViewAssetLoader(unittest.TestCase):
    """Category 3: AndroidX WebViewAssetLoader Virtual Origin Integration."""

    @classmethod
    def setUpClass(cls):
        cls.kt_content = ANDROID_MAIN_ACTIVITY_KT.read_text(encoding="utf-8") if ANDROID_MAIN_ACTIVITY_KT.is_file() else ""
        cls.gradle_content = ANDROID_BUILD_GRADLE_KTS.read_text(encoding="utf-8") if ANDROID_BUILD_GRADLE_KTS.is_file() else ""
        cls.toml_content = ANDROID_LIBS_VERSIONS_TOML.read_text(encoding="utf-8") if ANDROID_LIBS_VERSIONS_TOML.is_file() else ""

    def test_t1_3_androidx_webkit_dependency_in_catalog(self):
        """T1.3.1: androidx.webkit dependency is defined in libs.versions.toml."""
        self.assertIn("androidxWebkit", self.toml_content, "androidxWebkit version key missing")
        has_coord = (
            "androidx.webkit:webkit" in self.toml_content
            or ('group = "androidx.webkit"' in self.toml_content and 'name = "webkit"' in self.toml_content)
        )
        self.assertTrue(has_coord, "androidx.webkit dependency missing in libs.versions.toml")

    def test_t1_3_androidx_webkit_dependency_in_build_gradle(self):
        """T1.3.2: androidx.webkit is included in app/build.gradle.kts dependencies."""
        pattern = re.compile(r"implementation\s*\(\s*libs\.androidx\.webkit\s*\)")
        self.assertTrue(
            pattern.search(self.gradle_content),
            "app/build.gradle.kts must include implementation(libs.androidx.webkit)",
        )

    def test_t1_3_webview_asset_loader_builder_instantiated(self):
        """T1.3.3: WebViewAssetLoader.Builder() is instantiated in MainActivity.kt."""
        self.assertIn("WebViewAssetLoader.Builder()", self.kt_content)
        self.assertIn("AssetsPathHandler", self.kt_content)

    def test_t1_3_virtual_domain_configured(self):
        """T1.3.4: Virtual domain appassets.androidplatform.net is configured."""
        self.assertIn(
            "appassets.androidplatform.net",
            self.kt_content,
            "ASSET_DOMAIN must be 'appassets.androidplatform.net'",
        )

    def test_t1_3_virtual_url_loaded_over_https(self):
        """T1.3.5: WebView loads URL via https://appassets.androidplatform.net/assets/index.html."""
        pattern = re.compile(r"https://appassets\.androidplatform\.net/assets/index\.html")
        self.assertTrue(
            pattern.search(self.kt_content) or "VIRTUAL_BASE_URL" in self.kt_content,
            "MainActivity.kt must load https://appassets.androidplatform.net/assets/index.html",
        )

    def test_t1_3_should_intercept_request_implemented(self):
        """T1.3.6: WebViewClient overrides shouldInterceptRequest calling assetLoader."""
        self.assertIn("override fun shouldInterceptRequest", self.kt_content)
        self.assertIn("assetLoader.shouldInterceptRequest", self.kt_content)


class TestTier1ContentSecurityPolicy(unittest.TestCase):
    """Category 4: Web Content Security Policy (CSP) Configuration."""

    @classmethod
    def setUpClass(cls):
        cls.html_content = WEB_INDEX_HTML.read_text(encoding="utf-8") if WEB_INDEX_HTML.is_file() else ""
        cls.csp_raw = extract_csp_from_html(cls.html_content)
        cls.directives = parse_csp(cls.csp_raw) if cls.csp_raw else {}

    def test_t1_4_csp_meta_tag_present(self):
        """T1.4.1: index.html defines a Content-Security-Policy meta tag."""
        self.assertIsNotNone(self.csp_raw, "Missing <meta http-equiv='Content-Security-Policy'> tag in index.html")

    def test_t1_4_default_src_restrictive(self):
        """T1.4.2: default-src is restrictive ('none' or 'self')."""
        default_src = self.directives.get("default-src", [])
        self.assertTrue(
            "'none'" in default_src or "'self'" in default_src,
            f"default-src must be 'none' or 'self', found: {default_src}",
        )

    def test_t1_4_script_src_restricted_to_self(self):
        """T1.4.3: script-src restricts scripts to 'self' and disallows unpinned CDN and unsafe-eval."""
        script_src = self.directives.get("script-src", [])
        self.assertIn("'self'", script_src, "script-src must include 'self'")
        self.assertNotIn("'unsafe-eval'", script_src, "script-src must NOT contain 'unsafe-eval'")
        self.assertNotIn("https://cdn.tailwindcss.com", script_src, "script-src must NOT contain cdn.tailwindcss.com")

    def test_t1_4_style_src_allows_fonts_and_self(self):
        """T1.4.4: style-src allows 'self', 'unsafe-inline' (for player), and fonts.googleapis.com."""
        style_src = self.directives.get("style-src", [])
        self.assertIn("'self'", style_src, "style-src must contain 'self'")
        self.assertIn("https://fonts.googleapis.com", style_src, "style-src must contain https://fonts.googleapis.com")

    def test_t1_4_font_src_allows_gstatic(self):
        """T1.4.5: font-src allows 'self' and https://fonts.gstatic.com."""
        font_src = self.directives.get("font-src", [])
        self.assertIn("'self'", font_src, "font-src must contain 'self'")
        self.assertIn("https://fonts.gstatic.com", font_src, "font-src must contain https://fonts.gstatic.com")

    def test_t1_4_connect_and_media_src_restricted(self):
        """T1.4.6: media-src and connect-src restrict network endpoints."""
        media_src = self.directives.get("media-src", [])
        connect_src = self.directives.get("connect-src", [])
        self.assertIn("'self'", media_src, "media-src must include 'self'")
        self.assertIn("'self'", connect_src, "connect-src must include 'self'")
        self.assertNotIn("*", connect_src, "connect-src must NOT allow wildcard *")


class TestTier1StaticTailwindSupplyChain(unittest.TestCase):
    """Category 5: Static Tailwind CSS Supply Chain Hardening."""

    @classmethod
    def setUpClass(cls):
        cls.html_content = WEB_INDEX_HTML.read_text(encoding="utf-8") if WEB_INDEX_HTML.is_file() else ""
        cls.css_path = WEB_TAILWIND_CSS
        cls.css_content = cls.css_path.read_text(encoding="utf-8") if cls.css_path.is_file() else ""

    def test_t1_5_no_unpinned_tailwind_cdn_script(self):
        """T1.5.1: cdn.tailwindcss.com script is completely eliminated from index.html."""
        self.assertNotIn(
            "cdn.tailwindcss.com",
            self.html_content,
            "index.html must NOT contain runtime cdn.tailwindcss.com script tag",
        )

    def test_t1_5_no_inline_tailwind_config(self):
        """T1.5.2: Inline tailwind.config script is removed from index.html."""
        self.assertNotIn(
            "tailwind.config =",
            self.html_content,
            "index.html must NOT contain inline tailwind.config assignment",
        )

    def test_t1_5_tailwind_min_css_exists(self):
        """T1.5.3: tailwind.min.css exists in Okasha_Hafs_App and is non-empty."""
        self.assertTrue(self.css_path.is_file(), f"Missing {self.css_path}")
        self.assertGreater(self.css_path.stat().st_size, 5000, "tailwind.min.css is suspiciously small (< 5 KB)")

    def test_t1_5_tailwind_min_css_linked(self):
        """T1.5.4: index.html links to tailwind.min.css via <link rel='stylesheet'>."""
        pattern = re.compile(r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\'](?:\./)?tailwind\.min\.css["\']')
        pattern_alt = re.compile(r'<link[^>]+href=["\'](?:\./)?tailwind\.min\.css["\'][^>]+rel=["\']stylesheet["\']')
        self.assertTrue(
            pattern.search(self.html_content) or pattern_alt.search(self.html_content),
            "index.html must link tailwind.min.css",
        )

    def test_t1_5_css_contains_custom_tokens(self):
        """T1.5.5: tailwind.min.css contains custom emerald and gold tokens."""
        self.assertTrue(
            "emerald" in self.css_content or "#03120d" in self.css_content or "#07241b" in self.css_content,
            "tailwind.min.css missing emerald palette tokens",
        )
        self.assertTrue(
            "gold" in self.css_content or "#fae392" in self.css_content or "#e5b839" in self.css_content,
            "tailwind.min.css missing gold palette tokens",
        )


class TestTier1ServiceWorkerSameOrigin(unittest.TestCase):
    """Category 6: Service Worker Same-Origin Boundary Isolation."""

    @classmethod
    def setUpClass(cls):
        cls.sw_content = WEB_SW_JS.read_text(encoding="utf-8") if WEB_SW_JS.is_file() else ""

    def test_t1_6_sw_file_exists(self):
        """T1.6.1: sw.js exists in Okasha_Hafs_App."""
        self.assertTrue(WEB_SW_JS.is_file(), f"Missing {WEB_SW_JS}")

    def test_t1_6_origin_boundary_check_enforced(self):
        """T1.6.2: sw.js enforces origin boundary check on fetch requests."""
        pattern = re.compile(r"url\.origin\s*!==\s*self\.location\.origin|url\.origin\s*===\s*self\.location\.origin")
        self.assertTrue(
            pattern.search(self.sw_content),
            "sw.js must check url.origin against self.location.origin",
        )

    def test_t1_6_only_get_requests_cached(self):
        """T1.6.3: sw.js verifies request.method === 'GET' before caching."""
        pattern = re.compile(r"request\.method\s*!==?\s*['\"]GET['\"]|request\.method\s*===?\s*['\"]GET['\"]")
        self.assertTrue(
            pattern.search(self.sw_content),
            "sw.js must restrict caching to GET requests only",
        )

    def test_t1_6_fetch_event_listener_registered(self):
        """T1.6.4: sw.js registers a fetch event listener."""
        self.assertIn("addEventListener('fetch'", self.sw_content)

    def test_t1_6_cross_origin_requests_bypassed(self):
        """T1.6.5: sw.js returns early when origin does not match."""
        # Find fetch listener block
        fetch_idx = self.sw_content.find("addEventListener('fetch'")
        self.assertGreater(fetch_idx, -1, "Fetch listener not found")
        fetch_block = self.sw_content[fetch_idx:fetch_idx + 600]
        self.assertTrue(
            "origin" in fetch_block and "return" in fetch_block,
            "Fetch event listener must return early for cross-origin requests",
        )


class TestTier1CacheNamingSynchronization(unittest.TestCase):
    """Category 7: Cache Naming and Version Synchronization."""

    @classmethod
    def setUpClass(cls):
        cls.sw_content = WEB_SW_JS.read_text(encoding="utf-8") if WEB_SW_JS.is_file() else ""
        cls.app_content = WEB_APP_JS.read_text(encoding="utf-8") if WEB_APP_JS.is_file() else ""

    def test_t1_7_sw_cache_name_is_v2(self):
        """T1.7.1: sw.js sets CACHE_NAME to 'okasha-hafs-v2.0'."""
        pattern = re.compile(r"CACHE_NAME\s*=\s*['\"]okasha-hafs-v2\.0['\"]")
        self.assertTrue(
            pattern.search(self.sw_content),
            "sw.js must set CACHE_NAME to 'okasha-hafs-v2.0'",
        )

    def test_t1_7_app_js_cache_name_is_v2(self):
        """T1.7.2: app.js uses 'okasha-hafs-v2.0' for offline caching."""
        pattern = re.compile(r"caches\.open\(\s*['\"]okasha-hafs-v2\.0['\"]\s*\)")
        self.assertTrue(
            pattern.search(self.app_content),
            "app.js must open 'okasha-hafs-v2.0'",
        )

    def test_t1_7_no_outdated_cache_names_in_sw(self):
        """T1.7.3: Outdated cache names (v1.5, v1.6) do not appear in sw.js."""
        self.assertNotIn("okasha-hafs-v1.5", self.sw_content)
        self.assertNotIn("okasha-hafs-v1.6", self.sw_content)

    def test_t1_7_no_outdated_cache_names_in_app(self):
        """T1.7.4: Outdated cache names (v1.5, v1.6) do not appear in app.js."""
        self.assertNotIn("okasha-hafs-v1.5", self.app_content)
        self.assertNotIn("okasha-hafs-v1.6", self.app_content)

    def test_t1_7_static_assets_includes_tailwind_css(self):
        """T1.7.5: STATIC_ASSETS array in sw.js includes tailwind.min.css."""
        self.assertTrue(
            "./tailwind.min.css" in self.sw_content or "tailwind.min.css" in self.sw_content,
            "sw.js STATIC_ASSETS must include tailwind.min.css",
        )

    def test_t1_7_sw_activate_purges_stale_caches(self):
        """T1.7.6: sw.js activate handler deletes stale caches."""
        self.assertIn("caches.delete", self.sw_content)
        self.assertIn("keys.filter", self.sw_content)


class TestTier1RepositoryHygiene(unittest.TestCase):
    """Category 8: Repository Hygiene and Git Privacy."""

    @classmethod
    def setUpClass(cls):
        cls.web_git = WEB_GITIGNORE.read_text(encoding="utf-8") if WEB_GITIGNORE.is_file() else ""
        cls.android_git = ANDROID_GITIGNORE.read_text(encoding="utf-8") if ANDROID_GITIGNORE.is_file() else ""

    def test_t1_8_web_gitignore_exists(self):
        """T1.8.1: .gitignore exists in Okasha_Hafs_App."""
        self.assertTrue(WEB_GITIGNORE.is_file(), f"Missing {WEB_GITIGNORE}")

    def test_t1_8_web_gitignore_protects_sensitive_files(self):
        """T1.8.2: Okasha_Hafs_App/.gitignore ignores agents, idea, node_modules."""
        self.assertIn(".agents/", self.web_git)
        self.assertIn(".idea/", self.web_git)
        self.assertIn("node_modules/", self.web_git)

    def test_t1_8_android_gitignore_exists(self):
        """T1.8.3: .gitignore exists in OkashaHafsAndroid."""
        self.assertTrue(ANDROID_GITIGNORE.is_file(), f"Missing {ANDROID_GITIGNORE}")

    def test_t1_8_android_gitignore_protects_keystores_and_build(self):
        """T1.8.4: OkashaHafsAndroid/.gitignore ignores keystores, .gradle, build, local.properties."""
        self.assertIn("*.jks", self.android_git)
        self.assertIn(".gradle/", self.android_git)
        self.assertIn("build/", self.android_git)
        self.assertIn("local.properties", self.android_git)

    def test_t1_8_no_launch_app_bat_in_android_assets(self):
        """T1.8.5: launch_app.bat is not present in Android assets directory."""
        bat_file = ANDROID_ASSETS_DIR / "launch_app.bat"
        self.assertFalse(bat_file.exists(), "Extraneous launch_app.bat must not be in Android assets")

    def test_t1_8_audio_files_intact(self):
        """T1.8.6: All 9 expected audio files exist in audio/ and are non-empty."""
        self.assertTrue(WEB_AUDIO_DIR.is_dir(), f"Missing {WEB_AUDIO_DIR}")
        for audio_name in EXPECTED_AUDIO_FILES:
            file_path = WEB_AUDIO_DIR / audio_name
            self.assertTrue(file_path.is_file(), f"Missing audio file: {audio_name}")
            self.assertGreater(file_path.stat().st_size, 100_000, f"Audio file {audio_name} is too small (<100KB)")


if __name__ == "__main__":
    unittest.main()
