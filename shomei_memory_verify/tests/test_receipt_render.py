"""The human-readable renderer must be HONEST BY CONSTRUCTION: certification language only for an
AUTHENTICATED (pinned-key) result, an explicit downgrade for unpinned, no certificate for an invalid
receipt, disposition-accurate wording, and the non-claims emitted verbatim. These tests mint receipts
locally with a throwaway ed25519 key (NO engine import) so they ship in the open verifier repo."""
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shomei_memory_verify import render, verify_signed_receipt
from shomei_memory_verify._canonical import canonical_bytes, sha256_hex

_RAW, _RAWPUB = _ser.Encoding.Raw, _ser.PublicFormat.Raw


def _mint(body, sk=None):
    sk = sk or Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(_RAW, _RAWPUB).hex()
    cb = canonical_bytes(body)
    return {"schema": body.get("schema", ""), "receipt_hash": sha256_hex(cb), "signer_id": "shomei-receipt:acme",
            "public_key_hex": pk, "signature_hex": sk.sign(cb).hex(), "body": body}, pk


def _closure(disp="complete", erased=100, deferred=0):
    return {"schema": "shomei.subject_closure.v1", "tenant_id_hash": "hmac-sha256:abcd",
            "subject_pseudonym": "hmac-sha256:4d5fd529deadbeef", "closed_set_commitment": "hmac-sha256:f138",
            "closed_count": 100, "matched_count": 100, "erased_count": erased, "deferred_count": deferred,
            "disposition": disp, "match_basis": "exact_user_id", "applied_at": 1781585654}


def test_authenticated_complete_renders_certificate():
    r, pk = _mint(_closure())
    out = render(r, expected_public_key_hex=pk)
    assert "VERIFIED ✓" in out and "## What this certifies" in out
    assert "have been erased from the governed memory store" in out
    assert "COMPLETE" in out and "**100**" in out
    assert "How to verify this yourself" in out
    assert "ASSERTS" not in out                          # not downgraded


def test_unpinned_is_downgraded_never_certified():
    r, _ = _mint(_closure())
    out = render(r)                                       # NO pin -> valid but not authenticated
    assert "VERIFIED ✓" not in out
    assert "SELF-CONSISTENT ONLY" in out and "did NOT pin" in out
    assert "## What this receipt ASSERTS" in out
    assert "ASSERTED (pending the verification above) to have been erased" in out
    assert "## What this certifies" not in out           # the established-only header must be absent


def test_invalid_receipt_renders_no_certificate():
    r, pk = _mint(_closure())
    r["body"]["erased_count"] = 1                         # tamper AFTER signing -> sig/hash fail
    out = render(r, expected_public_key_hex=pk)
    assert "VERIFICATION FAILED" in out and "NOT A VALID RECEIPT" in out
    assert "## What this certifies" not in out
    assert "Right-to-be-Forgotten" not in out            # not dressed up as a certificate


def test_disposition_language_is_accurate():
    # (disposition, matched, erased, deferred, label_that_must_appear) — realistic per-case counts.
    cases = [("complete", 4, 4, 0, "COMPLETE"),
             ("partial", 3, 2, 1, "PARTIAL"),
             ("deferred", 2, 0, 2, "DEFERRED"),
             ("noop_no_match", 0, 0, 0, "NO MATCH")]
    FALSE_ERASURE = "have been erased from the governed memory store"   # the certified-erasure lead clause
    for disp, m, e, d, label in cases:
        body = {**_closure(disp=disp, erased=e, deferred=d), "matched_count": m, "closed_count": m}
        r, pk = _mint(body)
        out = render(r, expected_public_key_hex=pk)
        lead = out.split("**Disposition")[0]          # the opening clause, before the disposition label
        assert label in out, (disp, label)
        if disp == "complete":
            assert FALSE_ERASURE in lead              # complete: stating erasure in the lead is correct
        else:
            # partial / deferred / noop: the lead must NOT claim a blanket erasure happened
            assert FALSE_ERASURE not in lead, (disp, "lead falsely asserts blanket erasure")
        if disp == "noop_no_match":
            assert "NOTHING was erased" in lead
        if disp == "deferred":
            assert "have NOT yet been erased" in lead and "AUTO-FIRES on release" in out


def test_nonclaims_emitted_verbatim_regardless_of_pin():
    r, pk = _mint(_closure())
    for kw in render(r, expected_public_key_hex=pk), render(r):   # authenticated AND unpinned
        assert "does NOT assert removal from anything the data was copied or derived into" in kw
        assert "pseudonymized-with-proof, not unlinkable-anonymized" in kw


def test_renderer_does_not_leak_arbitrary_body_fields():
    body = _closure(); body["user_id"] = "alice.carter@example.com"   # a raw identity smuggled into the body
    r, pk = _mint(body)
    out = render(r, expected_public_key_hex=pk)
    assert "alice.carter@example.com" not in out          # renderer prints only known, safe fields


def test_delete_receipt_renders():
    body = {"schema": "shomei.vector_delete.v1", "tenant_id_hash": "hmac-sha256:ab", "memory_id": "mem_abc123",
            "tombstone_id": "sha256:dead", "key_custody": "kms", "physical_purge_state": "physical_purge_pending"}
    r, pk = _mint(body)
    out = render(r, expected_public_key_hex=pk)
    assert "Record Deletion Receipt" in out and "mem_abc123" in out
    assert "encryption key was destroyed" in out and "kms" in out


def test_restriction_receipt_renders_applied_and_lifted():
    a, pka = _mint({"schema": "shomei.restriction.v1", "memory_id": "mem_x", "action": "applied",
                    "restricted_state": True, "reason_code": "art18_request", "applied_at": 1781585654})
    out = render(a, expected_public_key_hex=pka)
    assert "RESTRICTED" in out and "Art.18" in out and "reversible" in out
    b, pkb = _mint({"schema": "shomei.restriction.v1", "memory_id": "mem_x", "action": "released",
                    "restricted_state": False, "reason_code": "art18_lifted", "applied_at": 1781585999})
    assert "LIFTED" in render(b, expected_public_key_hex=pkb)


def test_unknown_schema_does_not_crash():
    r, pk = _mint({"schema": "shomei.future.v9", "foo": "bar"})
    out = render(r, expected_public_key_hex=pk)
    assert "VERIFIED ✓" in out and "not available" in out      # honest generic, with the verification status


def test_render_accepts_a_verifyresult_too():
    r, pk = _mint(_closure())
    vr = verify_signed_receipt(r, expected_public_key_hex=pk)
    assert "VERIFIED ✓" in render(vr)
