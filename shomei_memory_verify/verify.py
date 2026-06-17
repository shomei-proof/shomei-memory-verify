"""Top-level public API: independently verify a Shomei signed receipt.

``verify_signed_receipt`` is the one call an auditor / data subject / regulator needs. It returns a
structured result that distinguishes two very different things:

  * ``valid``         — the envelope is well-formed, the ed25519 signature is internally consistent
                        over the body, and ``receipt_hash == sha256(canonical body)``.
  * ``authenticated`` — AND that signature was checked against a public key the CALLER pinned
                        (``expected_public_key_hex``), obtained out-of-band.

A ``valid`` receipt that is not ``authenticated`` proves only that the receipt is self-consistent —
an attacker can mint a perfectly ``valid`` receipt by signing arbitrary content with their OWN key
and embedding that key. So a trust decision ("did the operator really delete this?") MUST require
``authenticated`` / a pinned key. ``bool(result)`` is authentication-gated for exactly this reason.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Union

from .receipt import SignedReceipt


def _signed_schema(sr: SignedReceipt) -> str:
    """The schema as it appears in the SIGNED body (trustworthy). The envelope-level ``schema`` is
    unsigned, so it is deliberately never surfaced as authoritative."""
    v = sr.body.get("schema", "")
    return v if isinstance(v, str) else str(v)


@dataclass(frozen=True)
class VerifyResult:
    valid: bool                 # well-formed + ed25519 signature consistent over the body + hash matches
    authenticated: bool         # AND the signature was checked against a caller-PINNED public key;
                                #   valid-but-not-authenticated == self-consistent only, proves no authorship
    reason: str                 # 'ok' | 'ok_unpinned' | 'public_key_mismatch'
                                #   | 'signature_or_hash_invalid' | 'malformed: <detail>'
    public_key_hex: str = ""    # the key the signature verifies under = the authenticated signer identity
                                #   (trustworthy only when authenticated=True). Base trust decisions on THIS.
    schema: str = ""            # the SIGNED schema (from the body). The envelope-level schema is unsigned
                                #   and is NOT surfaced here.
    signer_id: str = ""         # ADVISORY ONLY — unsigned envelope metadata an attacker can relabel.
    body: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        # Truthy only when AUTHENTICATED, so a bare ``if verify_signed_receipt(r):`` cannot pass on a
        # receipt signed by an unpinned (attacker-chosen) key. Check ``.valid`` explicitly if you only
        # want internal consistency.
        return self.authenticated


def verify_signed_receipt(
    receipt: Union[SignedReceipt, Mapping[str, Any]],
    *,
    expected_public_key_hex: Optional[str] = None,
) -> VerifyResult:
    """Verify a Shomei signed receipt with public-key crypto alone, offline, using only the public key.

    SECURITY — pin the key. A signature only proves authorship relative to a TRUSTED key. Pass
    ``expected_public_key_hex`` (the signer's key, obtained out-of-band) to get an AUTHENTICATED
    result. WITHOUT it, a structurally-valid receipt is returned as ``valid=True, authenticated=False,
    reason='ok_unpinned'`` — self-consistent, but an attacker could have signed it with their own key,
    so it carries NO operator-trust guarantee.

    Only SIGNED values are surfaced as authoritative: ``schema`` comes from the signed body, and
    ``public_key_hex`` is the authenticated signer identity. ``signer_id`` is unsigned envelope
    metadata (advisory only). Accepts a ``SignedReceipt`` or a plain mapping (e.g. parsed JSON).
    """
    if isinstance(receipt, SignedReceipt):
        sr: SignedReceipt = receipt
    else:
        try:
            sr = SignedReceipt.from_dict(receipt)
        except ValueError as exc:
            return VerifyResult(False, False, f"malformed: {exc}")

    if expected_public_key_hex is not None and sr.public_key_hex != expected_public_key_hex:
        return VerifyResult(False, False, "public_key_mismatch",
                            public_key_hex=sr.public_key_hex, schema=_signed_schema(sr),
                            signer_id=sr.signer_id, body=sr.body)

    ok = sr.signature_valid(expected_public_key_hex=expected_public_key_hex)
    authenticated = ok and expected_public_key_hex is not None
    reason = "signature_or_hash_invalid" if not ok else ("ok" if authenticated else "ok_unpinned")
    return VerifyResult(ok, authenticated, reason,
                        public_key_hex=sr.public_key_hex, schema=_signed_schema(sr),
                        signer_id=sr.signer_id, body=sr.body)
