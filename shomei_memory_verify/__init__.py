"""Shomei Memory Verify — standalone, offline verifier for Shomei deletion/governance receipts.

Public-key-only verification of signed governance receipts: anyone holding a receipt + the
signer's public key can confirm it, without trusting the operator and without any access to the
governed-memory engine.

    from shomei_memory_verify import verify_signed_receipt
    result = verify_signed_receipt(receipt_json)          # a SignedReceipt or parsed-JSON mapping
    assert result.valid                                   # ed25519 signature + receipt_hash both check
    print(result.body["key_custody"])                     # the receipt's own assertions

This package verifies a receipt's ed25519 signature over canonical JSON. It imports only
``cryptography`` plus the standard library (zero engine code), an invariant enforced by
``tests/test_import_guard.py``. No network, no key material.
"""
from .receipt import SignedReceipt
from .receipt_render import render, to_html
from .verify import VerifyResult, verify_signed_receipt

__version__ = "0.0.2"
__all__ = ["SignedReceipt", "VerifyResult", "verify_signed_receipt", "render", "to_html", "__version__"]
