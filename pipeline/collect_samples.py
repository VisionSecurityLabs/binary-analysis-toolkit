"""
Collect malicious PE samples from MalwareBazaar (abuse.ch).

Usage:
    python pipeline/collect_samples.py --tag AgentTesla --limit 50
    python pipeline/collect_samples.py --tag Emotet Remcos --limit 100 --out samples/

MalwareBazaar is a free, public threat intelligence platform.
Samples are returned as ZIP archives with password "infected".
"""

from __future__ import annotations

import argparse
import io
import re
import struct
import time
import pyzipper
from pathlib import Path

import os

import requests
from dotenv import load_dotenv

load_dotenv()

BAZAAR_API = os.getenv("BAZAAR_API_URL", "https://mb-api.abuse.ch/api/v1/")
BAZAAR_AUTH_KEY = os.getenv("BAZAAR_AUTH_KEY", "")
DEFAULT_OUT = Path(os.getenv("SAMPLES_DIR", "samples"))
REQUEST_DELAY = 0.5  # seconds between download requests (be a good citizen)
MAX_SAMPLE_SIZE = 50 * 1024 * 1024  # 50 MB cap on extracted sample size
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _bazaar_headers() -> dict[str, str]:
    headers = {}
    if BAZAAR_AUTH_KEY:
        headers["Auth-Key"] = BAZAAR_AUTH_KEY
    return headers


def _is_pe(data: bytes) -> bool:
    """Check for MZ magic and PE signature."""
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data):
        return False
    return data[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def query_samples_by_tag(tag: str, limit: int = 100) -> list[dict]:
    """Return sample metadata list from MalwareBazaar for a given tag."""
    resp = requests.post(
        BAZAAR_API,
        headers=_bazaar_headers(),
        data={"query": "get_taginfo", "tag": tag, "limit": limit},
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("query_status") != "ok":
        print(f"  [!] Tag '{tag}': {payload.get('query_status')}")
        return []
    return payload.get("data", [])


def download_sample(sha256: str, out_dir: Path) -> Path | None:
    """Download a sample ZIP from MalwareBazaar, extract the PE, return path or None."""
    if not _SHA256_RE.match(sha256):
        print(f"  [!] Invalid SHA256 hash, skipping: {sha256[:64]}")
        return None

    out_path = out_dir / f"{sha256}.exe"
    if out_path.exists():
        return out_path  # already have it

    try:
        resp = requests.post(
            BAZAAR_API,
            headers=_bazaar_headers(),
            data={"query": "get_file", "sha256_hash": sha256},
            timeout=60,
        )
        resp.raise_for_status()

        # Response is an AES-256 encrypted ZIP with password "infected"
        zf = pyzipper.AESZipFile(io.BytesIO(resp.content))
        names = zf.namelist()
        if not names:
            return None

        info = zf.getinfo(names[0])
        if info.file_size > MAX_SAMPLE_SIZE:
            print(f"  [!] Sample too large ({info.file_size} bytes), skipping: {sha256[:16]}")
            return None

        raw = zf.read(names[0], pwd=b"infected")
        if not _is_pe(raw):
            return None  # skip non-PE content

        out_path.write_bytes(raw)
        return out_path

    except Exception as e:
        print(f"  [!] Download failed for {sha256[:16]}…: {e}")
        return None


def collect(tags: list[str], limit: int, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    downloaded: list[Path] = []
    seen: set[str] = set()
    manifest: dict[str, dict] = {}

    # Load existing manifest if present
    manifest_path = out_dir / "family_manifest.json"
    if manifest_path.exists():
        import json
        with open(manifest_path) as f:
            manifest = json.load(f)

    for tag in tags:
        print(f"\n[*] Querying MalwareBazaar: tag={tag!r}, limit={limit}")
        samples = query_samples_by_tag(tag, limit)
        print(f"    Found {len(samples)} entries")

        for meta in samples:
            sha256 = meta.get("sha256_hash", "")
            family = meta.get("signature") or meta.get("tags", [tag])[0]
            if not sha256 or sha256 in seen:
                continue
            seen.add(sha256)

            path = download_sample(sha256, out_dir)
            if path:
                downloaded.append(path)
                manifest[sha256] = {"family": family, "tag": tag}
                print(f"    [+] {sha256[:16]}…  {family:20s}  → {path.name}")
            else:
                print(f"    [-] {sha256[:16]}…  skipped (not PE or error)")

            time.sleep(REQUEST_DELAY)

    # Save family manifest
    import json
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[*] Family manifest → {manifest_path} ({len(manifest)} entries)")

    print(f"\n[*] Total downloaded: {len(downloaded)} PE files → {out_dir}/")
    return downloaded


def main():
    parser = argparse.ArgumentParser(description="Download malicious PEs from MalwareBazaar")
    parser.add_argument("--tag", nargs="+", default=["AgentTesla"], metavar="TAG",
                        help="Malware tag(s) to query (default: AgentTesla)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max samples per tag (default: 50)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help=f"Output directory (default: {DEFAULT_OUT})")
    args = parser.parse_args()

    collect(args.tag, args.limit, args.out)


if __name__ == "__main__":
    main()
