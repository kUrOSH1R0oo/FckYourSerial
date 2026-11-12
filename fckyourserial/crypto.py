"""
crypto.py — Key derivation, AES-CBC encryption and HMAC signing.

Implements the protection routines used by ASP.NET's
ObjectStateFormatter / LosFormatter when <machineKey> uses:

    validation="SHA1"  decryption="AES"

including the NIST SP 800-108 counter-mode KDF (HMAC-SHA512) that
ASP.NET 4.5+ applies to machineKey values before use.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import List, Optional, Tuple

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    raise ImportError(
        "Missing dependency — run:  pip install pycryptodome"
    )


# ---------------------------------------------------------------------------
# VLQ helpers (also used by payload patching, exposed here for reuse)
# ---------------------------------------------------------------------------

def write_vlq(n: int) -> bytes:
    """7-bit variable-length quantity used by BinaryFormatter / ObjectStateFormatter."""
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def write_vlq_string(s: str) -> bytes:
    """VLQ length-prefixed UTF-8 string."""
    data = s.encode("utf-8")
    return write_vlq(len(data)) + data


def _write_uint(v: int) -> bytes:
    return struct.pack(">I", v)


# ---------------------------------------------------------------------------
# NIST SP 800-108 key derivation (ASP.NET 4.5+)
# ---------------------------------------------------------------------------

def sp800_108_derivekey(
    key: bytes,
    label: Optional[bytes],
    context: Optional[bytes],
    key_length_bits: int,
) -> bytes:
    """NIST SP 800-108 Counter-mode KDF with HMAC-SHA512 (ASP.NET implementation)."""
    lbl = label or b""
    ctx = context or b""
    buffer = b"\x00" * 4 + lbl + b"\x00" + ctx + _write_uint(key_length_bits)
    out_len = key_length_bits // 8
    result = bytearray(out_len)
    offset = 0
    counter = 1
    while offset < out_len:
        block = _write_uint(counter) + buffer[4:]
        digest = hmac.new(key, block, hashlib.sha512).digest()
        take = min(len(digest), out_len - offset)
        result[offset : offset + take] = digest[:take]
        offset += take
        counter += 1
    return bytes(result)


def sp800_108_get_key_derivation_parameters(
    primary_purpose: str, specific_purposes: List[str]
) -> Tuple[bytes, bytes]:
    """Build the (label, context) pair ASP.NET feeds into the SP800-108 KDF."""
    label = primary_purpose.encode("utf-8")
    context = b"".join(write_vlq_string(p) for p in specific_purposes)
    return label, context


# ---------------------------------------------------------------------------
# Protect (encrypt + MAC)
# ---------------------------------------------------------------------------

def encrypt_and_sign(
    plaintext: bytes,
    decryption_key: bytes,
    validation_key: bytes,
    iv: Optional[bytes] = None,
) -> bytes:
    """
    AES-CBC (PKCS#7) + HMAC-SHA1 over (IV || ciphertext).
    Output layout:  IV || ciphertext || MAC
    """
    if iv is None:
        iv = os.urandom(16)

    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad] * pad)

    ct = AES.new(decryption_key, AES.MODE_CBC, iv).encrypt(padded)
    blob = iv + ct
    mac = hmac.new(validation_key, blob, hashlib.sha1).digest()
    return blob + mac
