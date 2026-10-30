"""
Shared configuration, paths, and helper utilities for Okasha Hafs E2E Test Suite.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Base Project Directories
TESTS_DIR = Path(__file__).resolve().parent
WEB_DIR = Path(os.environ.get("OKASHA_WEB_DIR", str(TESTS_DIR.parent))).resolve()
ANDROID_DIR = Path(os.environ.get("OKASHA_ANDROID_DIR", str(WEB_DIR.parent / "OkashaHafsAndroid"))).resolve()

# Web / PWA Paths
WEB_INDEX_HTML = WEB_DIR / "index.html"
WEB_APP_JS = WEB_DIR / "app.js"
WEB_SW_JS = WEB_DIR / "sw.js"
WEB_STYLE_CSS = WEB_DIR / "style.css"
WEB_TAILWIND_CSS = WEB_DIR / "tailwind.min.css"
WEB_MANIFEST_JSON = WEB_DIR / "manifest.json"
WEB_AUDIO_DIR = WEB_DIR / "audio"
WEB_GITIGNORE = WEB_DIR / ".gitignore"

# Android Native Paths
ANDROID_APP_DIR = ANDROID_DIR / "app"
ANDROID_SRC_MAIN = ANDROID_APP_DIR / "src" / "main"
ANDROID_MANIFEST_XML = ANDROID_SRC_MAIN / "AndroidManifest.xml"
ANDROID_MAIN_ACTIVITY_KT = ANDROID_SRC_MAIN / "java" / "com" / "example" / "okashahafs" / "MainActivity.kt"
ANDROID_ASSETS_DIR = ANDROID_SRC_MAIN / "assets"
ANDROID_BUILD_GRADLE_KTS = ANDROID_APP_DIR / "build.gradle.kts"
ANDROID_SETTINGS_GRADLE_KTS = ANDROID_DIR / "settings.gradle.kts"
ANDROID_LIBS_VERSIONS_TOML = ANDROID_DIR / "gradle" / "libs.versions.toml"
ANDROID_GRADLEW_BAT = ANDROID_DIR / "gradlew.bat"
ANDROID_GITIGNORE = ANDROID_DIR / ".gitignore"

# Expected Recitation Filenames (9 Forensically Verified Surahs)
EXPECTED_AUDIO_FILES = [
    "006_Al-Anam_29_59_Hafs.mp3",
    "015_Al-Hijr.mp3",
    "020_Taha_1_16_Hafs.mp3",
    "023_Al-Muminun_84_90_Hafs.mp3",
    "035_Fatir_15_24_Hafs.mp3",
    "035_Fatir_Hafs.mp3",
    "037_As-Saffat_Hafs.mp3",
    "040_Ghafir_38_50_Hafs.mp3",
    "066_At-Tahrim_Complete.mp3",
]


def parse_csp(csp_str: str) -> Dict[str, List[str]]:
    """
    Parse a Content Security Policy string into a directive -> token list mapping.
    """
    directives: Dict[str, List[str]] = {}
    tokens = [d.strip() for d in csp_str.split(";") if d.strip()]
    for token in tokens:
        parts = token.split()
        if not parts:
            continue
        directive_name = parts[0].lower()
        directive_values = parts[1:]
        directives[directive_name] = directive_values
    return directives


def extract_csp_from_html(html_content: str) -> Optional[str]:
    """
    Extract CSP policy content from <meta http-equiv="Content-Security-Policy" content="...">.
    Handles quotes within the content value properly.
    """
    # Case 1: http-equiv first, then content="..." or content='...'
    pattern1 = re.compile(
        r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=(?:"([^"]*)"|\'([^\']*)\')',
        re.IGNORECASE,
    )
    match1 = pattern1.search(html_content)
    if match1:
        return match1.group(1) if match1.group(1) is not None else match1.group(2)

    # Case 2: content first, then http-equiv
    pattern2 = re.compile(
        r'<meta[^>]+content=(?:"([^"]*)"|\'([^\']*)\')[^>]+http-equiv=["\']Content-Security-Policy["\']',
        re.IGNORECASE,
    )
    match2 = pattern2.search(html_content)
    if match2:
        return match2.group(1) if match2.group(1) is not None else match2.group(2)

    return None


def parse_android_manifest(manifest_path: Path = ANDROID_MANIFEST_XML) -> ET.Element:
    """
    Parse AndroidManifest.xml and return root Element.
    """
    tree = ET.parse(str(manifest_path))
    return tree.getroot()


def get_free_port() -> int:
    """
    Find a free ephemeral TCP port for local test servers.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def run_command(cmd: List[str], cwd: Path, timeout: float = 60.0) -> Tuple[int, str, str]:
    """
    Execute a subprocess command cleanly and return (exit_code, stdout, stderr).
    """
    process = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return -1, stdout, f"Timeout expired after {timeout} seconds"
