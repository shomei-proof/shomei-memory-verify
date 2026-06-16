"""CONFORMANCE (public, engine-free): the standalone verifier accepts a committed golden receipt and
rejects every tampering.

This test SHIPS in the public repo — it imports NO engine code; its only input is the static fixture
``tests/fixtures/golden_receipt.json`` (a real engine-signed receipt over a generic body). The
engine<->verifier canonicalization-AGREEMENT and golden-is-current checks live in the PRIVATE
``tests/_engine_backed/`` suite, which is excluded from public release.
"""
import json
import pathlib

import pytest

from shomei_memory_verify import SignedReceipt, verify_signed_receipt

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "golden_receipt.json"


def _golden() -> dict:
    return json.loads(FIXTURE.read_text())


def test_unpinned_is_valid_but_NOT_authenticated():
    # Without a pinned key the receipt is only self-consistent — it must NOT pass as authenticated,
    # and bool(result) (the trust gate) must be falsy.
    res = verify_signed_receipt(_golden())
    assert res.valid and not res.authenticated and res.reason == "ok_unpinned"
    assert not res                                   # bool() is authentication-gated
    assert res.body["key_custody"] == "kms"          # the receipt's own (signed) assertion is surfaced


def test_pinned_correct_key_authenticates():
    g = _golden()
    res = verify_signed_receipt(g, expected_public_key_hex=g["public_key_hex"])
    assert res.valid and res.authenticated and res.reason == "ok"
    assert res                                       # truthy only when authenticated
    assert res.schema == "shomei.governed_delete.example.v1"   # the SIGNED schema
    assert res.public_key_hex == g["public_key_hex"]           # authenticated signer identity


def test_pinned_wrong_key_is_rejected():
    g = _golden()
    bad = verify_signed_receipt(g, expected_public_key_hex="00" * 32)
    assert not bad.valid and not bad.authenticated and bad.reason == "public_key_mismatch"


def test_envelope_metadata_is_not_trusted():
    # The signature covers the BODY only. An attacker can relabel the unsigned envelope schema /
    # signer_id on a genuine receipt; the verifier must surface the SIGNED schema (not the envelope's)
    # and never treat signer_id as authenticated.
    g = _golden()
    g["signer_id"] = "acme-trusted-auditor"               # forged, unsigned
    g["schema"] = "shomei.SOMETHING-ELSE.v9"              # forged envelope schema (unsigned)
    res = verify_signed_receipt(g, expected_public_key_hex=g["public_key_hex"])
    assert res.valid and res.authenticated                # signature still valid (body untouched)
    assert res.schema == "shomei.governed_delete.example.v1"   # SIGNED schema, not the forged envelope one
    # signer_id is advisory/unsigned — it reflects whatever the envelope claimed (caller must not trust it)
    assert res.signer_id == "acme-trusted-auditor"


def test_tampered_body_fails():
    g = _golden()
    g["body"] = {**g["body"], "key_custody": "tpm_simulated"}   # forge a stronger-looking tier
    res = verify_signed_receipt(g)
    assert not res.valid and res.reason == "signature_or_hash_invalid"


def test_tampered_receipt_hash_fails():
    g = _golden()
    g["receipt_hash"] = "sha256:" + "0" * 64
    assert not verify_signed_receipt(g).valid


def test_forged_signature_fails():
    g = _golden()
    g["signature_hex"] = "00" * 64
    assert not verify_signed_receipt(g).valid


@pytest.mark.parametrize("drop", ["schema", "receipt_hash", "signer_id",
                                  "public_key_hex", "signature_hex", "body"])
def test_malformed_envelope_is_rejected_not_crashed(drop):
    g = _golden()
    del g[drop]
    res = verify_signed_receipt(g)
    assert not res.valid and res.reason.startswith("malformed")


def test_signedreceipt_object_input_also_works():
    assert verify_signed_receipt(SignedReceipt.from_dict(_golden())).valid
