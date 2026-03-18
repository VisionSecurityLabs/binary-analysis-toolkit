"""Validators for reducing false positives on pattern matches."""

import hashlib

_B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def is_valid_bitcoin_address(addr: str) -> bool:
    """Validate a base58check Bitcoin address (P2PKH/P2SH, not bech32).

    Returns True if the checksum is valid, False otherwise.
    """
    try:
        # Base58 decode
        n = 0
        for c in addr.encode('ascii'):
            n = n * 58 + _B58_ALPHABET.index(c)
        # Convert to 25 bytes
        data = n.to_bytes(25, 'big')
        # Last 4 bytes are checksum
        payload, checksum = data[:-4], data[-4:]
        return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    except (ValueError, OverflowError):
        return False
