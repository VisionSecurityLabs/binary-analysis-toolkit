"""
Collect malicious PE samples from MalwareBazaar (abuse.ch).

Usage:
    uv run python pipeline/collect_samples.py --tag AgentTesla --limit 50
    uv run python pipeline/collect_samples.py --tag Emotet Remcos --limit 100 --out samples/
    uv run python pipeline/collect_samples.py --filetype exe dll --limit 100 --out samples/

MalwareBazaar is a free, public threat intelligence platform.
Samples are returned as ZIP archives with password "infected".
"""

from __future__ import annotations

import argparse
import io
import json
import re
import struct
import time
import pyzipper
from pathlib import Path

import os

import requests
from requests import Response
from dotenv import load_dotenv

load_dotenv()

BAZAAR_API = os.getenv("BAZAAR_API_URL", "https://mb-api.abuse.ch/api/v1/")
BAZAAR_AUTH_KEY = os.getenv("BAZAAR_AUTH_KEY", "")
DEFAULT_OUT = Path(os.getenv("SAMPLES_DIR", "samples"))
REQUEST_DELAY = 0.5  # seconds between download requests (be a good citizen)
MAX_SAMPLE_SIZE = 50 * 1024 * 1024  # 50 MB cap on extracted sample size
BAZAAR_QUERY_TIMEOUT = int(os.getenv("BAZAAR_QUERY_TIMEOUT", "60"))
BAZAAR_DOWNLOAD_TIMEOUT = int(os.getenv("BAZAAR_DOWNLOAD_TIMEOUT", "180"))
BAZAAR_RETRIES = int(os.getenv("BAZAAR_RETRIES", "3"))
BAZAAR_RETRY_BACKOFF = float(os.getenv("BAZAAR_RETRY_BACKOFF", "2.0"))
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


def _post_with_retries(
    data: dict[str, str | int],
    timeout: int,
    action_label: str,
    retries: int = BAZAAR_RETRIES,
    backoff: float = BAZAAR_RETRY_BACKOFF,
) -> Response:
    """POST to MalwareBazaar with retry/backoff for transient failures."""
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(
                BAZAAR_API,
                headers=_bazaar_headers(),
                data=data,
                timeout=timeout,
            )
            if resp.status_code >= 500:
                raise requests.HTTPError(
                    f"{resp.status_code} Server Error: {resp.reason} for url: {resp.url}",
                    response=resp,
                )
            resp.raise_for_status()
            return resp
        except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
            last_exc = exc
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            retryable = (
                isinstance(exc, (requests.Timeout, requests.ConnectionError))
                or (status_code is not None and status_code >= 500)
            )
            if not retryable or attempt >= retries:
                break
            sleep_for = backoff * attempt
            print(f"  [!] {action_label}: transient error ({exc}); retrying in {sleep_for:.1f}s [{attempt}/{retries}]")
            time.sleep(sleep_for)
    assert last_exc is not None
    raise last_exc


def _query_samples(
    query: str,
    key: str,
    value: str,
    limit: int = 100,
    timeout: int = BAZAAR_QUERY_TIMEOUT,
    retries: int = BAZAAR_RETRIES,
    backoff: float = BAZAAR_RETRY_BACKOFF,
) -> list[dict]:
    """Return sample metadata list from MalwareBazaar for a given query type."""
    resp = _post_with_retries(
        {"query": query, key: value, "limit": limit},
        timeout,
        f"query {key}={value!r}",
        retries,
        backoff,
    )
    payload = resp.json()
    if payload.get("query_status") != "ok":
        print(f"  [!] {key}={value!r}: {payload.get('query_status')}")
        return []
    return payload.get("data", [])


def query_samples_by_tag(
    tag: str,
    limit: int = 100,
    timeout: int = BAZAAR_QUERY_TIMEOUT,
    retries: int = BAZAAR_RETRIES,
    backoff: float = BAZAAR_RETRY_BACKOFF,
) -> list[dict]:
    """Return sample metadata list from MalwareBazaar for a given tag."""
    return _query_samples("get_taginfo", "tag", tag, limit, timeout, retries, backoff)


def query_samples_by_filetype(
    file_type: str,
    limit: int = 100,
    timeout: int = BAZAAR_QUERY_TIMEOUT,
    retries: int = BAZAAR_RETRIES,
    backoff: float = BAZAAR_RETRY_BACKOFF,
) -> list[dict]:
    """Return sample metadata list from MalwareBazaar for a given file type."""
    return _query_samples("get_file_type", "file_type", file_type, limit, timeout, retries, backoff)


def download_sample(
    sha256: str,
    out_path: Path,
    timeout: int = BAZAAR_DOWNLOAD_TIMEOUT,
    retries: int = BAZAAR_RETRIES,
    backoff: float = BAZAAR_RETRY_BACKOFF,
) -> Path | None:
    """Download a sample ZIP from MalwareBazaar, extract the PE, return path or None."""
    if not _SHA256_RE.match(sha256):
        print(f"  [!] Invalid SHA256 hash, skipping: {sha256[:64]}")
        return None

    if out_path.exists():
        return out_path  # already have it

    try:
        resp = _post_with_retries(
            {"query": "get_file", "sha256_hash": sha256},
            timeout,
            f"download {sha256[:16]}…",
            retries,
            backoff,
        )

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


def sample_path(sha256: str, out_dir: Path) -> Path:
    return out_dir / f"{sha256}.exe"


def sample_extension(meta: dict, fallback: str) -> str:
    for key in ("file_type", "file_type_guess"):
        value = meta.get(key)
        if isinstance(value, str):
            value = value.strip().lower().lstrip(".")
            if value and re.fullmatch(r"[a-z0-9]{1,10}", value):
                return value

    for key in ("file_name", "filename"):
        value = meta.get(key)
        if isinstance(value, str):
            suffix = Path(value).suffix.strip().lower().lstrip(".")
            if suffix and re.fullmatch(r"[a-z0-9]{1,10}", suffix):
                return suffix

    fallback = fallback.strip().lower().lstrip(".")
    return fallback or "bin"


def sample_path_with_extension(sha256: str, extension: str, out_dir: Path) -> Path:
    ext = extension.strip().lower().lstrip(".") or "bin"
    return out_dir / f"{sha256}.{ext}"


def find_existing_sample(sha256: str, out_dir: Path) -> Path | None:
    matches = sorted(out_dir.glob(f"{sha256}.*"))
    for path in matches:
        if path.name.endswith(("_analysis.json", "_analysis.html")):
            continue
        if path.name in {"family_manifest.json", "batch_summary.json"}:
            continue
        if path.is_file():
            return path
    return None


def repair_sample_extensions(out_dir: Path, manifest: dict[str, dict]) -> int:
    renamed = 0
    for sha256, meta in manifest.items():
        if not isinstance(meta, dict):
            continue
        desired_ext = (
            str(meta.get("extension") or meta.get("file_type") or "").strip().lower().lstrip(".")
        )
        if not desired_ext or not _SHA256_RE.match(sha256):
            continue

        current_path = find_existing_sample(sha256, out_dir)
        if current_path is None:
            continue

        current_ext = current_path.suffix.lstrip(".").lower()
        if current_ext == desired_ext:
            continue

        target_path = sample_path_with_extension(sha256, desired_ext, out_dir)
        if target_path.exists() and target_path != current_path:
            continue

        current_path.rename(target_path)
        meta["extension"] = desired_ext
        renamed += 1
        print(f"  [~] Renamed {current_path.name} -> {target_path.name}")
    return renamed


def sample_family(meta: dict, fallback: str) -> str:
    signature = meta.get("signature")
    if isinstance(signature, str) and signature.strip():
        return signature.strip()

    tags = meta.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.strip():
                return tag.strip()

    return fallback


def load_manifest(manifest_path: Path) -> dict[str, dict]:
    if not manifest_path.exists():
        return {}
    try:
        with open(manifest_path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError as exc:
        print(f"  [!] Corrupted manifest at {manifest_path}: {exc}")
        print("  [!] Rebuilding manifest from this run.")
        return {}


def collect(
    tags: list[str],
    filetypes: list[str],
    limit: int,
    out_dir: Path,
    query_timeout: int = BAZAAR_QUERY_TIMEOUT,
    download_timeout: int = BAZAAR_DOWNLOAD_TIMEOUT,
    retries: int = BAZAAR_RETRIES,
    backoff: float = BAZAAR_RETRY_BACKOFF,
    repair_only: bool = False,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    downloaded: list[Path] = []
    already_present: list[Path] = []
    seen: set[str] = set()
    manifest: dict[str, dict] = {}

    # Load existing manifest if present
    manifest_path = out_dir / "family_manifest.json"
    manifest = load_manifest(manifest_path)
    repaired = repair_sample_extensions(out_dir, manifest)
    if repaired:
        print(f"[*] Repaired {repaired} sample extension(s) in {out_dir}")
    elif repair_only:
        print(f"[*] No sample extensions needed repair in {out_dir}")

    if repair_only:
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        return []

    query_specs: list[tuple[str, str]] = []
    query_specs.extend(("tag", tag) for tag in tags)
    query_specs.extend(("file_type", file_type) for file_type in filetypes)

    if not query_specs:
        raise ValueError("At least one tag or file type must be provided")

    for query_kind, query_value in query_specs:
        print(f"\n[*] Querying MalwareBazaar: {query_kind}={query_value!r}, limit={limit}")
        if query_kind == "tag":
            samples = query_samples_by_tag(query_value, limit, query_timeout, retries, backoff)
        else:
            samples = query_samples_by_filetype(query_value, limit, query_timeout, retries, backoff)
        print(f"    Found {len(samples)} entries")

        for meta in samples:
            sha256 = meta.get("sha256_hash", "")
            family = sample_family(meta, query_value)
            if not sha256 or sha256 in seen:
                continue
            seen.add(sha256)

            extension = sample_extension(meta, query_value)
            existing_path = find_existing_sample(sha256, out_dir)
            if existing_path is not None:
                already_present.append(existing_path)
                entry = manifest.setdefault(sha256, {"family": family})
                entry["family"] = family
                entry["extension"] = existing_path.suffix.lstrip(".").lower()
                if query_kind == "tag":
                    entry["tag"] = query_value
                else:
                    entry["file_type"] = query_value
                print(f"    [=] {sha256[:16]}…  {family:20s}  already present")
                continue

            out_path = sample_path_with_extension(sha256, extension, out_dir)
            path = download_sample(sha256, out_path, download_timeout, retries, backoff)
            if path:
                downloaded.append(path)
                entry = manifest.setdefault(sha256, {"family": family})
                entry["family"] = family
                entry["extension"] = path.suffix.lstrip(".").lower()
                if query_kind == "tag":
                    entry["tag"] = query_value
                else:
                    entry["file_type"] = query_value
                print(f"    [+] {sha256[:16]}…  {family:20s}  → {path.name}")
            else:
                print(f"    [-] {sha256[:16]}…  skipped (not PE or error)")

            time.sleep(REQUEST_DELAY)

    # Save family manifest
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[*] Family manifest → {manifest_path} ({len(manifest)} entries)")

    print(f"\n[*] Newly downloaded: {len(downloaded)} PE files")
    print(f"[*] Already present: {len(already_present)} PE files")
    print(f"[*] Samples directory: {out_dir}/")
    return downloaded


def main():
    parser = argparse.ArgumentParser(description="Download malicious PEs from MalwareBazaar")
    parser.add_argument("--tag", nargs="+", default=[], metavar="TAG",
                        help="Malware tag(s) to query")
    parser.add_argument("--filetype", nargs="+", default=[], metavar="TYPE",
                        help="MalwareBazaar file type(s) to query, e.g. exe dll elf")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max samples per query value (default: 50)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help=f"Output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--query-timeout", type=int, default=BAZAAR_QUERY_TIMEOUT,
                        help=f"MalwareBazaar metadata query timeout in seconds (default: {BAZAAR_QUERY_TIMEOUT})")
    parser.add_argument("--download-timeout", type=int, default=BAZAAR_DOWNLOAD_TIMEOUT,
                        help=f"MalwareBazaar sample download timeout in seconds (default: {BAZAAR_DOWNLOAD_TIMEOUT})")
    parser.add_argument("--retries", type=int, default=BAZAAR_RETRIES,
                        help=f"Retry count for transient MalwareBazaar failures (default: {BAZAAR_RETRIES})")
    parser.add_argument("--retry-backoff", type=float, default=BAZAAR_RETRY_BACKOFF,
                        help=f"Base backoff in seconds between retries (default: {BAZAAR_RETRY_BACKOFF})")
    parser.add_argument("--repair-extensions-only", action="store_true",
                        help="Repair sample filename extensions from the local manifest and exit")
    args = parser.parse_args()

    tags = args.tag or []
    filetypes = args.filetype or []
    if not tags and not filetypes:
        tags = ["AgentTesla"]

    collect(
        tags,
        filetypes,
        args.limit,
        args.out,
        args.query_timeout,
        args.download_timeout,
        args.retries,
        args.retry_backoff,
        args.repair_extensions_only,
    )


if __name__ == "__main__":
    main()
