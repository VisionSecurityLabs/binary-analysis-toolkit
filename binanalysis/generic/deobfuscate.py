"""
deobfuscate.py - Simple string deobfuscation for pre-processing extracted binary strings.

Tries several common encoding/obfuscation techniques on each string and returns
any successfully decoded results. Intended to run before pattern matching so that
encoded payloads can be caught by existing rules.
"""

import base64
import re
import string

# Characters considered "printable" for deobfuscation quality checks.
# Excludes control characters (whitespace like \t, \n, \r are in string.printable
# but we only want visible/safe ASCII for decoded payloads).
_PRINTABLE = frozenset(
    c for c in string.printable if c not in string.whitespace or c == ' '
)

_MIN_LEN = 20
_PRINTABLE_THRESHOLD = 0.80


def _is_printable_enough(text: str) -> bool:
    """Return True if >80% of characters in text are printable non-control ASCII."""
    if not text:
        return False
    printable_count = sum(1 for c in text if c in _PRINTABLE)
    return (printable_count / len(text)) > _PRINTABLE_THRESHOLD


def _try_base64(s: str) -> str | None:
    """
    Attempt base64 decoding on s.

    Conditions for attempting:
    - Length >= 20
    - Only base64 alphabet characters: [A-Za-z0-9+/=]
    - Length divisible by 4

    Returns the decoded string if it is printable ASCII, else None.
    """
    if len(s) < _MIN_LEN:
        return None
    if len(s) % 4 != 0:
        return None
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return None
    try:
        decoded_bytes = base64.b64decode(s)
        decoded = decoded_bytes.decode('ascii', errors='replace')
    except Exception:
        return None
    if _is_printable_enough(decoded):
        return decoded
    return None


def _try_hex(s: str) -> str | None:
    """
    Attempt hex decoding on s.

    Conditions for attempting:
    - Matches ^[0-9a-fA-F]{20,}$ with even length

    Returns the decoded string if it is printable ASCII, else None.
    """
    if not re.fullmatch(r'[0-9a-fA-F]{20,}', s):
        return None
    if len(s) % 2 != 0:
        return None
    try:
        decoded_bytes = bytes.fromhex(s)
        decoded = decoded_bytes.decode('ascii', errors='replace')
    except Exception:
        return None
    if _is_printable_enough(decoded):
        return decoded
    return None


def _try_single_byte_xor(s: str) -> list[str]:
    """
    Attempt single-byte XOR brute force on hex-encoded byte sequences.

    Only tried on strings that look like high-entropy hex blobs
    (matches ^[0-9a-fA-F]{20,}$ with even length — same shape as hex decode
    but applied when hex decode itself didn't yield printable output).

    Tries XOR keys 0x01 through 0xFF. Returns a list of all decoded strings
    where >80% of bytes are printable ASCII and the result is 10+ chars.
    """
    if not re.fullmatch(r'[0-9a-fA-F]{20,}', s):
        return []
    if len(s) % 2 != 0:
        return []

    try:
        raw_bytes = bytes.fromhex(s)
    except Exception:
        return []

    results = []
    for key in range(0x01, 0x100):
        xored = bytes(b ^ key for b in raw_bytes)
        decoded = xored.decode('ascii', errors='replace')
        if len(decoded) < 10:
            continue
        printable_count = sum(1 for c in decoded if c in _PRINTABLE)
        if (printable_count / len(decoded)) > _PRINTABLE_THRESHOLD:
            results.append(decoded)
    return results


def deobfuscate_strings(raw_strings: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Take extracted strings and return additional decoded strings found within them.

    Each input element is a ``(offset, string)`` tuple as produced by the
    strings extraction stage.  Only strings of at least 20 characters are
    considered for deobfuscation.

    The following techniques are attempted on every qualifying string:

    1. Base64 decode — if the string is valid padded base64, decode and check
       printability.
    2. Hex decode — if the string is a hex blob of even length, decode and
       check printability.
    3. Single-byte XOR — if the string is a hex blob, brute-force XOR with
       keys 0x01–0xFF and collect all printable results.

    Returns NEW strings only (the decoded results), not the originals.
    The caller should append these to the original string list.

    Args:
        raw_strings: List of ``(offset, string)`` tuples from string extraction.

    Returns:
        List of ``(offset, decoded_string)`` tuples where the offset is
        inherited from the source string.
    """
    additional: list[tuple[int, str]] = []

    for offset, s in raw_strings:
        if len(s) < _MIN_LEN:
            continue

        # Base64
        b64_result = _try_base64(s)
        if b64_result is not None:
            additional.append((offset, b64_result))

        # Hex decode
        hex_result = _try_hex(s)
        if hex_result is not None:
            additional.append((offset, hex_result))

        # Single-byte XOR — tried independently on hex blobs regardless of
        # whether plain hex decode also succeeded, because the XOR brute-force
        # may recover an entirely different (and more meaningful) plaintext.
        xor_results = _try_single_byte_xor(s)
        for xr in xor_results:
            additional.append((offset, xr))

    return additional
