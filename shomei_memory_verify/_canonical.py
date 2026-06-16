"""Canonicalization + hashing for receipt verification.

VENDORED (byte-identical) from the governed engine's canonicalizer so this verifier stays a
STANDALONE leaf with ZERO engine imports. Canonicalization is RFC 8785 JCS (see ``_jcs.py``), so a
third party re-canonicalizing in ANY language/library computes the same bytes. The receipt format is
a stable wire contract; an engine-backed conformance suite mints with the real engine and asserts
this copy matches it byte-for-byte, so any drift fails CI before release (a committed golden-fixture
conformance test guards the same invariant with no engine present).

These functions must match the engine's canonicalization and commitment helpers BYTE-FOR-BYTE,
or signatures/hashes won't verify.
"""
from __future__ import annotations

import hashlib
from typing import Any

from ._jcs import canonicalize

SHA_PREFIX = "sha256:"


def canonical_bytes(obj: Any) -> bytes:
    """RFC 8785 JCS canonical UTF-8 bytes (vendored ``_jcs.canonicalize``). Fails closed on NaN/Inf,
    lone surrogates, non-string keys, and out-of-safe-range integers. Identical to the engine's
    signing encoding."""
    return canonicalize(obj)


def sha256_hex(data: bytes) -> str:
    """``sha256:<64hex>`` — the engine's witness/receipt-hash shape."""
    return SHA_PREFIX + hashlib.sha256(data).hexdigest()
