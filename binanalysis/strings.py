"""String extraction from raw binary data — ASCII and UTF-16LE (wide)."""

import re


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """Extract ASCII strings with their offsets."""
    results = []
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data):
        results.append((m.start(), m.group().decode('ascii', errors='replace')))
    return results


def extract_wide_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """Extract UTF-16LE (wide) strings with their offsets."""
    results = []
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len, data):
        try:
            decoded = m.group().decode('utf-16-le')
            results.append((m.start(), decoded))
        except Exception:
            pass
    return results
