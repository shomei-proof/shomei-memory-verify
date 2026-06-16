"""Shomei Memory Verify — standalone, offline verifier for Shomei deletion/governance receipts.

Public-key-only verification of signed governance receipts: anyone holding a receipt + the
signer's public key can confirm it, without trusting the operator and without any access to the
governed-memory engine.

    from shomei_memory_verify import verify_signed_receipt
    result = verify_signed_receipt(receipt_json)          # a SignedReceipt or parsed-JSON mapping
    assert result.valid                                   # ed25519 signature + receipt_hash both check
    print(result.body["key_custody"])                     # the receipt's own assertions

Design boundary (the "open the proof-checker, not the recipe" cut): this package verifies the
STRUCTURE of a proof; it never contains the engine's PRODUCTION method (crypto-erasure, decay
coarsening, the prover) or any private/signing key. It imports ZERO engine code — only
``cryptography`` — and that invariant is enforced by ``tests/test_import_guard.py``.
"""
from .receipt import SignedReceipt
from .receipt_render import render, to_html
from .verify import VerifyResult, verify_signed_receipt

__version__ = "0.0.2"
__all__ = ["SignedReceipt", "VerifyResult", "verify_signed_receipt", "render", "to_html", "__version__"]
