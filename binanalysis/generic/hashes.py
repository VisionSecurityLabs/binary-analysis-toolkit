"""File hash computation — format-agnostic."""

import hashlib
from pathlib import Path

from binanalysis.output import heading, detail


def analyze_hashes(filepath: Path, data: bytes) -> dict:
    heading("FILE HASHES")
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    detail("MD5", hashes["md5"])
    detail("SHA1", hashes["sha1"])
    detail("SHA256", hashes["sha256"])
    detail("File Size", f"{len(data)} bytes ({len(data)/1024:.1f} KB)")
    detail("File Name", filepath.name)
    return hashes
