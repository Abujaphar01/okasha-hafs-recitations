"""
Tier 4: Real-World Scenarios Test Suite.
Verifies end-to-end execution in real runtime environments:
1. Android Build Verification (assembleDebug & APK artifact) (4 tests)
2. Web App HTTP Serving on Localhost (5 tests)
3. Audio Streaming & Range Header Verification (4 tests)
"""

from __future__ import annotations

import json
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler
from pathlib import Path

# Add tests directory to sys.path
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from test_config import (
    ANDROID_APP_DIR,
    ANDROID_DIR,
    ANDROID_GRADLEW_BAT,
    EXPECTED_AUDIO_FILES,
    WEB_DIR,
    extract_csp_from_html,
    get_free_port,
    parse_csp,
)


class RangeHTTPRequestHandler(SimpleHTTPRequestHandler):
    """
    HTTP Request Handler supporting RFC 7233 / RFC 9110 Byte-Range Requests.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_HEAD(self):
        f = self.send_head()
        if f:
            f.close()

    def send_head(self):
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith('/'):
                self.send_response(301)
                new_parts = (parts[0], parts[1], parts[2] + '/', parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.send_header("Location", new_url)
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index_path = os.path.join(path, index)
                if os.path.exists(index_path):
                    path = index_path
                    break
            else:
                return super().send_head()

        ctype = self.guess_type(path)
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(404, "File not found")
            return None

        fs = os.fstat(f.fileno())
        total_len = fs[6]

        range_header = self.headers.get("Range")
        if range_header and range_header.startswith("bytes="):
            range_val = range_header[len("bytes="):].strip()
            parts = range_val.split("-")
            start = int(parts[0]) if parts[0] else 0
            end = int(parts[1]) if parts[1] else total_len - 1
            end = min(end, total_len - 1)

            if start > end or start >= total_len:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{total_len}")
                self.end_headers()
                f.close()
                return None

            content_len = end - start + 1
            self.send_response(206)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Range", f"bytes {start}-{end}/{total_len}")
            self.send_header("Content-Length", str(content_len))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()

            f.seek(start)
            # Create a bounded reader for the chunk
            return ChunkReader(f, content_len)

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(total_len))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        return f


class ChunkReader:
    """Wrapper that limits read length to chunk size."""

    def __init__(self, file_obj, max_bytes: int):
        self.file_obj = file_obj
        self.remaining = max_bytes

    def read(self, size=-1):
        if self.remaining <= 0:
            return b""
        read_size = self.remaining if size == -1 else min(size, self.remaining)
        data = self.file_obj.read(read_size)
        self.remaining -= len(data)
        return data

    def close(self):
        self.file_obj.close()


class TestTier4AndroidBuildScenario(unittest.TestCase):
    """Category 1: Real-World Android Native Build Execution."""

    def test_t4_1_gradle_wrapper_exists(self):
        """T4.1.1: gradlew.bat exists in Android directory and is executable."""
        self.assertTrue(ANDROID_GRADLEW_BAT.is_file(), f"Missing {ANDROID_GRADLEW_BAT}")

    def test_t4_1_gradle_build_configuration_valid(self):
        """T4.1.2: Gradle version and plugins evaluate cleanly."""
        cmd = ["cmd.exe", "/c", str(ANDROID_GRADLEW_BAT), "--version"]
        res = subprocess.run(cmd, cwd=str(ANDROID_DIR), capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 0, f"gradlew --version failed: {res.stderr}")
        self.assertIn("Gradle", res.stdout)

    def test_t4_1_assemble_debug_task_graph_valid(self):
        """T4.1.3: assembleDebug task graph executes cleanly with exit code 0."""
        cmd = ["cmd.exe", "/c", str(ANDROID_GRADLEW_BAT), "assembleDebug", "--dry-run"]
        res = subprocess.run(cmd, cwd=str(ANDROID_DIR), capture_output=True, text=True, timeout=45)
        self.assertEqual(res.returncode, 0, f"assembleDebug --dry-run failed: {res.stderr}")
        self.assertIn("BUILD SUCCESSFUL", res.stdout)

    def test_t4_1_debug_apk_built(self):
        """T4.1.4: Output APK app-debug.apk exists in build outputs and is valid size."""
        apk_path = ANDROID_APP_DIR / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
        self.assertTrue(apk_path.is_file(), f"Expected debug APK missing at {apk_path}")
        self.assertGreater(apk_path.stat().st_size, 1_000_000, "APK size is unexpectedly small (<1MB)")


class TestTier4WebHttpServingScenario(unittest.TestCase):
    """Category 2: Real-World Local HTTP Server Execution on 127.0.0.1."""

    server: socketserver.TCPServer
    server_thread: threading.Thread
    port: int

    @classmethod
    def setUpClass(cls):
        cls.port = get_free_port()
        cls.server = socketserver.TCPServer(("127.0.0.1", cls.port), RangeHTTPRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)  # Give server brief moment to bind

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}/{path.lstrip('/')}"

    def test_t4_2_serve_index_html(self):
        """T4.2.1: Server serves index.html with HTTP 200 and strict CSP meta tag."""
        req = urllib.request.Request(self._url("index.html"))
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            content = resp.read().decode("utf-8")
            csp = extract_csp_from_html(content)
            self.assertIsNotNone(csp, "index.html served without CSP meta tag")
            directives = parse_csp(csp)
            self.assertIn("'none'", directives.get("default-src", []))

    def test_t4_2_serve_tailwind_min_css(self):
        """T4.2.2: Server serves compiled tailwind.min.css with HTTP 200 and text/css."""
        req = urllib.request.Request(self._url("tailwind.min.css"))
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/css", resp.headers.get("Content-Type", ""))
            body = resp.read()
            self.assertGreater(len(body), 15000, "tailwind.min.css too small")

    def test_t4_2_serve_app_js(self):
        """T4.2.3: Server serves app.js with HTTP 200 and okasha-hafs-v2.0 cache name."""
        req = urllib.request.Request(self._url("app.js"))
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("okasha-hafs-v2.0", body)

    def test_t4_2_serve_sw_js(self):
        """T4.2.4: Server serves sw.js with HTTP 200, origin check, and v2.0 cache name."""
        req = urllib.request.Request(self._url("sw.js"))
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("okasha-hafs-v2.0", body)
            self.assertIn("self.location.origin", body)

    def test_t4_2_serve_manifest_json(self):
        """T4.2.5: Server serves manifest.json with valid PWA manifest JSON."""
        req = urllib.request.Request(self._url("manifest.json"))
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            manifest = json.loads(resp.read().decode("utf-8"))
            self.assertIn("name", manifest)
            self.assertIn("Okasha", manifest["name"])
            self.assertIn("icons", manifest)


class TestTier4AudioStreamingScenario(unittest.TestCase):
    """Category 3: Real-World HTTP Audio Streaming & Byte-Range Execution."""

    server: socketserver.TCPServer
    server_thread: threading.Thread
    port: int

    @classmethod
    def setUpClass(cls):
        cls.port = get_free_port()
        cls.server = socketserver.TCPServer(("127.0.0.1", cls.port), RangeHTTPRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}/{path.lstrip('/')}"

    def test_t4_3_audio_head_request(self):
        """T4.3.1: HEAD request on audio file returns Content-Type and Accept-Ranges: bytes."""
        audio_url = self._url("audio/015_Al-Hijr.mp3")
        req = urllib.request.Request(audio_url, method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Accept-Ranges"), "bytes")
            self.assertEqual(resp.headers.get("Content-Type"), "audio/mpeg")

    def test_t4_3_audio_initial_chunk_streaming(self):
        """T4.3.2: GET with Range: bytes=0-1023 returns HTTP 206 and exact byte slice."""
        audio_url = self._url("audio/015_Al-Hijr.mp3")
        req = urllib.request.Request(audio_url)
        req.add_header("Range", "bytes=0-1023")

        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 206)
            self.assertEqual(resp.headers.get("Content-Length"), "1024")
            self.assertTrue(resp.headers.get("Content-Range", "").startswith("bytes 0-1023/"))
            chunk = resp.read()
            self.assertEqual(len(chunk), 1024)

    def test_t4_3_audio_seeking_range(self):
        """T4.3.3: GET with Range: bytes=50000-99999 returns HTTP 206 and 50,000 bytes."""
        audio_url = self._url("audio/015_Al-Hijr.mp3")
        req = urllib.request.Request(audio_url)
        req.add_header("Range", "bytes=50000-99999")

        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 206)
            self.assertEqual(resp.headers.get("Content-Length"), "50000")
            self.assertTrue(resp.headers.get("Content-Range", "").startswith("bytes 50000-99999/"))
            chunk = resp.read()
            self.assertEqual(len(chunk), 50000)

    def test_t4_3_all_nine_recitations_accessible(self):
        """T4.3.4: All 9 recitation files stream audio chunks with HTTP 206."""
        for filename in EXPECTED_AUDIO_FILES:
            url = self._url(f"audio/{filename}")
            req = urllib.request.Request(url)
            req.add_header("Range", "bytes=0-511")
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 206, f"Failed streaming for {filename}")
                self.assertEqual(resp.headers.get("Content-Length"), "512")
                chunk = resp.read()
                self.assertEqual(len(chunk), 512, f"Incorrect chunk length for {filename}")


if __name__ == "__main__":
    unittest.main()
