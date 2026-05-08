"""JA4 fingerprint lookup tool."""

import json
import os
import urllib.request
import tempfile
import shutil
from strands import tool

CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "ja4db")
INDEX_PATH = os.path.join(CACHE_DIR, "ja4_index.json")
DB_URL = "https://ja4db.com/api/read/"

_index: dict | None = None


def _load_index() -> dict:
    """Load JA4 index from disk. Returns empty dict if unavailable."""
    global _index
    if _index is not None:
        return _index

    if not os.path.exists(INDEX_PATH):
        try:
            _update_index()
        except Exception:
            _index = {}
            return _index

    try:
        with open(INDEX_PATH) as f:
            _index = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        _index = {}
    return _index


def _update_index():
    """Download ja4db and build compact lookup index."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=CACHE_DIR)
    try:
        with urllib.request.urlopen(DB_URL, timeout=120) as resp:
            with os.fdopen(tmp_fd, "wb") as f:
                shutil.copyfileobj(resp, f)

        with open(tmp_path) as f:
            data = json.load(f)

        # Build index: fingerprint → {app, lib, os, verified, count}
        groups: dict[str, list] = {}
        for entry in data:
            fp = entry.get("ja4_fingerprint")
            if fp:
                groups.setdefault(fp, []).append(entry)

        index = {}
        for fp, entries in groups.items():
            record: dict = {"count": len(entries)}
            for entry in sorted(entries, key=lambda e: e.get("verified", False), reverse=True):
                if not record.get("app") and entry.get("application", "").strip():
                    record["app"] = entry["application"].strip()
                if not record.get("lib") and entry.get("library", "").strip():
                    record["lib"] = entry["library"].strip()
                if not record.get("os") and entry.get("os", "").strip():
                    record["os"] = entry["os"].strip()
                if entry.get("verified"):
                    record["verified"] = True
            index[fp] = record

        with open(INDEX_PATH, "w") as f:
            json.dump(index, f)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@tool
def lookup_ja4(fingerprints: str) -> str:
    """Look up JA4 TLS fingerprints to identify client software.

    JA4 fingerprints are found in WAF logs (ja4Fingerprint field). This tool
    identifies what application/library generated the TLS connection, helping
    distinguish real browsers from automation tools.

    Args:
        fingerprints: Comma-separated JA4 fingerprint strings to look up.
            Example: "t13d1516h2_8daaf6152771_02713d6af862,t13d1517h2_8daaf6152771_b0da82dd1658"

    Returns:
        For each fingerprint: identified application/library/OS, or "Unknown".
    """
    index = _load_index()
    fps = [fp.strip() for fp in fingerprints.split(",") if fp.strip()]

    if not fps:
        return "No fingerprints provided."

    if not index:
        return "JA4 database unavailable (offline or not yet downloaded). Cannot identify fingerprints."

    lines = []
    for fp in fps[:25]:  # limit to 25
        record = index.get(fp)
        if record:
            parts = []
            if record.get("app"):
                parts.append(f"App: {record['app']}")
            if record.get("lib"):
                parts.append(f"Lib: {record['lib']}")
            if record.get("os"):
                parts.append(f"OS: {record['os']}")
            verified = " ✓" if record.get("verified") else ""
            lines.append(f"  {fp} → {', '.join(parts)}{verified}")
        else:
            lines.append(f"  {fp} → Unknown (not in ja4db)")

    return f"JA4 Lookup ({len(fps)} fingerprint(s)):\n" + "\n".join(lines)
