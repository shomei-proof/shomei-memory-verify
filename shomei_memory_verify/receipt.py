"""The signed-receipt envelope + its public-key verification.

This is the VERIFY side only. There is deliberately NO signer / private-key path here — minting
receipts is the governed engine's job and stays closed. A third party holding only a receipt and
the signer's PUBLIC key can confirm it, offline, without trusting the operator and without any
access to the engine. Vendored to mirror the engine's ``SignedReceipt`` envelope shape exactly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._canonical import canonical_bytes, sha256_hex

_REQUIRED = ("schema", "receipt_hash", "signer_id", "public_key_hex", "signature_hex", "body")


@dataclass(frozen=True)
class SignedReceipt:
    """An ed25519-signed receipt envelope: the signature is over ``canonical_bytes(body)`` and
    ``receipt_hash`` is ``sha256(canonical_bytes(body))``. The ``body`` is opaque to the verifier
    (it carries the assertions — what was deleted, when, under what key custody); verification is
    schema-agnostic, so new receipt types verify without changing this code."""

    schema: str
    receipt_hash: str
    signer_id: str
    public_key_hex: str
    signature_hex: str
    body: Dict[str, Any]

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "SignedReceipt":
        if not isinstance(d, Mapping):
            raise ValueError(f"signed receipt must be a mapping, got {type(d).__name__}")
        missing = [k for k in _REQUIRED if k not in d]
        if missing:
            raise ValueError(f"malformed signed receipt: missing {missing}")
        if not isinstance(d["body"], Mapping):
            raise ValueError("malformed signed receipt: 'body' must be a mapping")
        return cls(
            schema=str(d["schema"]),
            receipt_hash=str(d["receipt_hash"]),
            signer_id=str(d["signer_id"]),
            public_key_hex=str(d["public_key_hex"]),
            signature_hex=str(d["signature_hex"]),
            body=dict(d["body"]),
        )

    def hash_matches(self) -> bool:
        """``receipt_hash`` is the honest digest of the canonical body."""
        return self.receipt_hash == sha256_hex(canonical_bytes(self.body))

    def signature_valid(self, *, expected_public_key_hex: Optional[str] = None) -> bool:
        """True iff the ed25519 signature is valid for the body under the embedded public key
        AND ``receipt_hash`` matches. If ``expected_public_key_hex`` is given, the signer's key
        must equal it (pin to a customer-approved signer)."""
        if expected_public_key_hex is not None and self.public_key_hex != expected_public_key_hex:
            return False
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key_hex))
            pk.verify(bytes.fromhex(self.signature_hex), canonical_bytes(self.body))
        except (InvalidSignature, ValueError):
            return False
        return self.hash_matches()
