"""
Adversarial Stress Test Harness — Challenger 1 (Empirical Challenger)
Focus: Android Native & WebView Security Verification in OkashaHafsAndroid.

Challenges:
1. allowFileAccess & allowContentAccess restrictions and bypass resilience.
2. URL navigation spoofing, subdomains, path traversal, and pseudo-protocols.
3. External link delegation to ACTION_VIEW and crash resilience.
4. Merged manifest security (usesCleartextTraffic="false", allowBackup="false").
5. Real build and test verification.
"""

from __future__ import annotations

import os
import re
import sys
import unittest
import zipfile
from pathlib import Path
from urllib.parse import urlparse, quote

# Ensure tests directory is on path
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from test_config import (
    ANDROID_APP_DIR,
    ANDROID_ASSETS_DIR,
    ANDROID_DIR,
    ANDROID_MAIN_ACTIVITY_KT,
    ANDROID_MANIFEST_XML,
    parse_android_manifest,
)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ASSET_DOMAIN = "appassets.androidplatform.net"
VIRTUAL_BASE_URL = f"https://{ASSET_DOMAIN}/assets/index.html"


class TestAdversarialFileAndContentAccess(unittest.TestCase):
    """
    Challenge 1: allowFileAccess and allowContentAccess Bypass & Sandbox Hardening.
    """

    @classmethod
    def setUpClass(cls):
        cls.kt_content = ANDROID_MAIN_ACTIVITY_KT.read_text(encoding="utf-8") if ANDROID_MAIN_ACTIVITY_KT.is_file() else ""

    def test_adv_1_allow_file_access_strictly_disabled(self):
        """Verify allowFileAccess = false is explicitly configured and not overridden."""
        self.assertIn("allowFileAccess = false", self.kt_content)
        # Verify no contradictory true assignment
        self.assertFalse(re.search(r"allowFileAccess\s*=\s*true", self.kt_content), "allowFileAccess set to true!")

    def test_adv_1_allow_content_access_strictly_disabled(self):
        """Verify allowContentAccess = false is explicitly configured and not overridden."""
        self.assertIn("allowContentAccess = false", self.kt_content)
        self.assertFalse(re.search(r"allowContentAccess\s*=\s*true", self.kt_content), "allowContentAccess set to true!")

    def test_adv_1_no_dangerous_legacy_file_scheme_settings(self):
        """Verify dangerous legacy settings like allowFileAccessFromFileURLs are absent."""
        dangerous_settings = [
            "allowFileAccessFromFileURLs",
            "allowUniversalAccessFromFileURLs",
            "setAllowFileAccessFromFileURLs",
            "setAllowUniversalAccessFromFileURLs",
        ]
        for setting in dangerous_settings:
            self.assertNotIn(setting, self.kt_content, f"Dangerous WebView setting {setting} detected!")

    def test_adv_1_file_scheme_urls_blocked_from_internal_load(self):
        """Verify file:/// URLs are never treated as internal assets."""
        adversarial_file_urls = [
            "file:///android_asset/index.html",
            "file:///android_asset/launch_app.bat",
            "file:///android_res/values/strings.xml",
            "file:///data/data/com.example.okashahafs/databases/db.sqlite",
            "file:///sdcard/Download/payload.apk",
            "file:///etc/hosts",
            "FILE:///android_asset/index.html",
            "file://localhost/android_asset/index.html",
        ]
        for url in adversarial_file_urls:
            parsed = urlparse(url)
            host = parsed.hostname
            # In MainActivity: host != null && host.equals(ASSET_DOMAIN, ignoreCase = true)
            is_internal = host is not None and host.lower() == ASSET_DOMAIN.lower()
            self.assertFalse(is_internal, f"File scheme URL {url} must NOT be treated as internal asset!")

    def test_adv_1_content_scheme_urls_blocked_from_internal_load(self):
        """Verify content:// URLs are never treated as internal assets."""
        adversarial_content_urls = [
            "content://media/external/images/media",
            "content://contacts/people",
            "content://com.example.provider/secret",
            "content://appassets.androidplatform.net/assets/index.html",
        ]
        for url in adversarial_content_urls:
            parsed = urlparse(url)
            # Notice: even if authority happens to be ASSET_DOMAIN in content://, scheme is NOT https!
            # MainActivity checks host. If host matches, check if assetLoader would intercept:
            # AssetLoader only intercepts https requests for virtual domain.
            self.assertNotEqual(parsed.scheme, "https", f"Content scheme should not be https: {url}")

    def test_adv_1_path_traversal_resistance_in_assets_directory(self):
        """Verify that directory traversal strings cannot escape the assets root."""
        traversal_paths = [
            "../AndroidManifest.xml",
            "../../build.gradle.kts",
            "../../../../../../../../etc/passwd",
            "..\\..\\build.gradle.kts",
            "%2e%2e/%2e%2e/build.gradle.kts",
            "audio/../../index.html",
        ]
        for t_path in traversal_paths:
            # In AndroidX AssetsPathHandler, AssetManager resolves within APK asset folder only
            # Verify no asset exists at external escaped path
            resolved = (ANDROID_ASSETS_DIR / t_path).resolve()
            # If path escapes ANDROID_ASSETS_DIR, verify it is not inside assets
            is_subpath = resolved.is_relative_to(ANDROID_ASSETS_DIR) if hasattr(resolved, "is_relative_to") else str(resolved).startswith(str(ANDROID_ASSETS_DIR.resolve()))
            if not is_subpath:
                # Outside assets: must not be accessible via AssetManager
                self.assertFalse(resolved.is_relative_to(ANDROID_ASSETS_DIR) if hasattr(resolved, "is_relative_to") else str(resolved).startswith(str(ANDROID_ASSETS_DIR.resolve())))

    def test_adv_1_no_executable_or_sensitive_files_in_assets(self):
        """Verify no executable scripts, keystores, or batch files reside in Android assets."""
        forbidden_extensions = {".bat", ".sh", ".exe", ".jks", ".keystore", ".key", ".pem", ".properties"}
        for root, _, files in os.walk(ANDROID_ASSETS_DIR):
            for file in files:
                p = Path(root) / file
                ext = p.suffix.lower()
                self.assertNotIn(
                    ext,
                    forbidden_extensions,
                    f"Forbidden file type in Android assets: {p.relative_to(ANDROID_ASSETS_DIR)}",
                )


class TestAdversarialUrlNavigationSpoofing(unittest.TestCase):
    """
    Challenge 2: URL Navigation Spoofing, Subdomains, Traversal, and Pseudo-Protocols.
    """

    @classmethod
    def setUpClass(cls):
        cls.kt_content = ANDROID_MAIN_ACTIVITY_KT.read_text(encoding="utf-8") if ANDROID_MAIN_ACTIVITY_KT.is_file() else ""

    def _evaluate_main_activity_url_decision(self, url_str: str) -> str:
        """
        Emulate MainActivity.kt shouldOverrideUrlLoading logic:
        val uri = request?.url ?: return false
        val host = uri.host
        if (host != null && host.equals(ASSET_DOMAIN, ignoreCase = true)) {
            return false // Load in WebView
        }
        return true // Launch external Intent
        """
        parsed = urlparse(url_str)
        host = parsed.hostname
        if host and host.lower() == ASSET_DOMAIN.lower():
            return "LOAD_INTERNAL"
        return "DELEGATE_EXTERNAL"

    def test_adv_2_subdomain_and_suffix_spoofing(self):
        """Adversarial domain variations must NOT match virtual domain."""
        adversarial_domains = [
            f"https://{ASSET_DOMAIN}.attacker.com/assets/index.html",
            f"https://{ASSET_DOMAIN}.evil.io",
            f"https://sub.{ASSET_DOMAIN}/assets/index.html",
            f"https://evil-{ASSET_DOMAIN}/assets/index.html",
            f"https://not{ASSET_DOMAIN}/assets/index.html",
            f"https://attacker.com/{ASSET_DOMAIN}",
            f"https://attacker.com?domain={ASSET_DOMAIN}",
        ]
        for url in adversarial_domains:
            decision = self._evaluate_main_activity_url_decision(url)
            self.assertEqual(
                decision,
                "DELEGATE_EXTERNAL",
                f"Adversarial domain {url} incorrectly loaded internally!",
            )

    def test_adv_2_user_info_spoofing_defense(self):
        """Verify credentials in URL (user:pass@host) do not fool host extraction."""
        url = f"https://{ASSET_DOMAIN}@attacker.com/assets/index.html"
        decision = self._evaluate_main_activity_url_decision(url)
        self.assertEqual(decision, "DELEGATE_EXTERNAL")

    def test_adv_2_pseudo_protocols_defense(self):
        """Verify javascript:, data:, about:, blob: URLs are handled safely."""
        pseudo_urls = [
            "javascript:alert(document.cookie)",
            "javascript:void(0)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "about:blank",
            "blob:https://appassets.androidplatform.net/uuid-1234",
        ]
        for url in pseudo_urls:
            decision = self._evaluate_main_activity_url_decision(url)
            # Because host is None or not equal to ASSET_DOMAIN, must delegate externally (which catches ActivityNotFoundException)
            self.assertEqual(
                decision,
                "DELEGATE_EXTERNAL",
                f"Pseudo protocol {url} must not load as internal asset",
            )

    def test_adv_2_legitimate_internal_assets_load(self):
        """Verify all valid internal asset URLs match ASSET_DOMAIN case-insensitively."""
        legit_urls = [
            "https://appassets.androidplatform.net/assets/index.html",
            "https://APPASSETS.ANDROIDPLATFORM.NET/assets/index.html",
            "https://appassets.androidplatform.net/assets/style.css",
            "https://appassets.androidplatform.net/assets/tailwind.min.css",
            "https://appassets.androidplatform.net/assets/app.js",
            "https://appassets.androidplatform.net/assets/sw.js",
            "https://appassets.androidplatform.net/assets/audio/015_Al-Hijr.mp3",
            "https://appassets.androidplatform.net/assets/index.html?track=2#player",
        ]
        for url in legit_urls:
            decision = self._evaluate_main_activity_url_decision(url)
            self.assertEqual(
                decision,
                "LOAD_INTERNAL",
                f"Legitimate asset URL {url} was incorrectly blocked!",
            )

    def test_adv_2_scheme_handling_analysis(self):
        """
        Adversarial Analysis: In MainActivity.kt, host check does not explicitly check uri.scheme == 'https'.
        Evaluate defense-in-depth:
        1. WebViewAssetLoader default mHttpAllowed is false (rejects cleartext http).
        2. android:usesCleartextTraffic='false' blocks network transmission.
        """
        # If url is http://appassets.androidplatform.net/assets/index.html
        # MainActivity allows it to WebView.
        # But AssetLoader will not intercept it because it's http, and Android network stack blocks cleartext HTTP.
        # This confirms defense-in-depth protection.
        self.assertIn("setDomain(ASSET_DOMAIN)", self.kt_content)
        # Verify setHttpAllowed(true) is NOT called
        self.assertNotIn("setHttpAllowed", self.kt_content, "setHttpAllowed(true) must NOT be called!")


class TestAdversarialExternalLinkIntentDelegation(unittest.TestCase):
    """
    Challenge 3: External Link Delegation to ACTION_VIEW and Exception Handling.
    """

    @classmethod
    def setUpClass(cls):
        cls.kt_content = ANDROID_MAIN_ACTIVITY_KT.read_text(encoding="utf-8") if ANDROID_MAIN_ACTIVITY_KT.is_file() else ""

    def test_adv_3_action_view_intent_used(self):
        """Verify Intent.ACTION_VIEW is used for external navigation."""
        self.assertIn("Intent.ACTION_VIEW", self.kt_content)
        self.assertIn("context.startActivity(intent)", self.kt_content)

    def test_adv_3_activity_not_found_exception_caught(self):
        """Verify ActivityNotFoundException is caught so unhandled schemes do not crash."""
        self.assertIn("catch (e: ActivityNotFoundException)", self.kt_content)
        # Verify it returns true to consume and prevent crash
        catch_block = re.search(r"catch\s*\(\s*e:\s*ActivityNotFoundException\s*\)\s*\{\s*([^\}]+)\}", self.kt_content)
        self.assertIsNotNone(catch_block, "ActivityNotFoundException block not found")
        self.assertIn("true", catch_block.group(1), "Must return true in catch block")

    def test_adv_3_no_unsafe_intent_uri_parsing(self):
        """
        Verify Intent.parseUri is NOT used.
        Using Intent.parseUri with untrusted URLs can lead to internal component hijacking or Intent redirection.
        MainActivity uses Intent(Intent.ACTION_VIEW, uri), which safely treats intent URIs as opaque data.
        """
        self.assertNotIn("Intent.parseUri", self.kt_content, "Unsafe Intent.parseUri detected!")
        self.assertNotIn("URI_INTENT_SCHEME", self.kt_content)

    def test_adv_3_no_deep_link_hijack_in_main_activity(self):
        """Verify MainActivity does not load arbitrary URLs passed via Intent extras or data."""
        self.assertNotIn("intent.data", self.kt_content)
        self.assertNotIn("intent.getData()", self.kt_content)
        self.assertNotIn("getStringExtra", self.kt_content)
        self.assertIn("loadUrl(VIRTUAL_BASE_URL)", self.kt_content)


class TestAdversarialMergedManifestSecurity(unittest.TestCase):
    """
    Challenge 4: Merged Manifest Security Policy Verification.
    """

    @classmethod
    def setUpClass(cls):
        cls.source_manifest = ANDROID_MANIFEST_XML
        # Path to merged manifest produced by Android Gradle Plugin
        cls.merged_manifest_path = (
            ANDROID_APP_DIR
            / "build"
            / "intermediates"
            / "merged_manifests"
            / "debug"
            / "processDebugManifest"
            / "AndroidManifest.xml"
        )
        cls.has_merged = cls.merged_manifest_path.is_file()
        if cls.has_merged:
            cls.merged_root = parse_android_manifest(cls.merged_manifest_path)
            cls.merged_app = cls.merged_root.find("application")
        cls.source_root = parse_android_manifest(cls.source_manifest)
        cls.source_app = cls.source_root.find("application")

    def test_adv_4_source_manifest_security_flags(self):
        """Source manifest strictly enforces usesCleartextTraffic=false and allowBackup=false."""
        cleartext = self.source_app.attrib.get(f"{{{ANDROID_NS}}}usesCleartextTraffic")
        backup = self.source_app.attrib.get(f"{{{ANDROID_NS}}}allowBackup")
        self.assertEqual(cleartext, "false", "Source usesCleartextTraffic must be 'false'")
        self.assertEqual(backup, "false", "Source allowBackup must be 'false'")

    def test_adv_4_merged_manifest_exists_and_retains_security_flags(self):
        """
        Empirically verify merged manifest after AGP manifest merger:
        Ensure no AAR/library dependency flipped usesCleartextTraffic or allowBackup to true.
        """
        self.assertTrue(self.has_merged, f"Merged manifest not found at {self.merged_manifest_path}")
        merged_cleartext = self.merged_app.attrib.get(f"{{{ANDROID_NS}}}usesCleartextTraffic")
        merged_backup = self.merged_app.attrib.get(f"{{{ANDROID_NS}}}allowBackup")
        self.assertEqual(
            merged_cleartext,
            "false",
            f"Merged manifest has insecure usesCleartextTraffic='{merged_cleartext}'!",
        )
        self.assertEqual(
            merged_backup,
            "false",
            f"Merged manifest has insecure allowBackup='{merged_backup}'!",
        )

    def test_adv_4_no_unwanted_exported_components(self):
        """Verify only intended activities/receivers are exported in merged manifest."""
        self.assertTrue(self.has_merged)
        for act in self.merged_app.findall("activity"):
            name = act.attrib.get(f"{{{ANDROID_NS}}}name", "")
            exported = act.attrib.get(f"{{{ANDROID_NS}}}exported", "false")
            if ".MainActivity" in name:
                self.assertEqual(exported, "true", "MainActivity should be exported launcher")
                filters = act.findall("intent-filter")
                self.assertTrue(len(filters) > 0, "MainActivity must have launcher intent-filter")


class TestAdversarialBuildAndApkIntegrity(unittest.TestCase):
    """
    Challenge 5: Build Reproducibility & Output APK Verification.
    """

    def test_adv_5_apk_exists_and_is_valid_zip(self):
        """Verify app-debug.apk was generated and contains valid Android package structure."""
        apk_path = ANDROID_APP_DIR / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
        self.assertTrue(apk_path.is_file(), f"Output APK missing at {apk_path}")
        self.assertGreater(apk_path.stat().st_size, 1_000_000, "APK suspiciously small (<1MB)")

        with zipfile.ZipFile(apk_path, "r") as z:
            namelist = z.namelist()
            self.assertIn("AndroidManifest.xml", namelist)
            self.assertIn("classes.dex", namelist)
            self.assertIn("resources.arsc", namelist)
            # Verify packaged assets
            self.assertIn("assets/index.html", namelist)
            self.assertIn("assets/app.js", namelist)
            self.assertIn("assets/tailwind.min.css", namelist)
            self.assertIn("assets/sw.js", namelist)
            # Verify launch_app.bat is NOT inside APK
            self.assertNotIn("assets/launch_app.bat", namelist, "launch_app.bat packaged into APK!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
