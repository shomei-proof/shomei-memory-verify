# Shomei Memory Verify

**Offline, independent verification of Shomei Memory governance receipts.**

When a Shomei Memory deployment erases a subject's data (GDPR Art. 17 "right to be
forgotten"), restricts it (Art. 18), or deletes a record, it emits a small, content-free,
ed25519-signed **receipt**. This package lets *anyone* — a DPO, General Counsel, auditor, or
the data subject — confirm that receipt on their own machine, using only:

1. the receipt file, and
2. the signer's published public key (obtained out-of-band),

with **no access to the operator's systems** and **no trust in the operator's word**.

## The "open verifier" boundary

This package is the *proof-checker*, not the *recipe*. It verifies the **structure of a proof**
— it does **not** contain the production engine (crypto-erasure, predictive decay, the prover) or
any private/signing key. Its **only** third-party dependency is
[`cryptography`](https://pypi.org/project/cryptography/); everything else is the Python standard
library. That minimal, auditable surface is the point: you can read all of it in an afternoon.

## Install

```bash
pip install shomei-memory-verify
```

## Verify a receipt (CLI)

```bash
# Prints a one-page, plain-language certificate; exits 0 ONLY if the signature
# authenticates against the key you pinned.
shomei-memory-verify receipt.json --pin <signer_public_key_hex> --render
```

Useful variants:

```bash
shomei-memory-verify receipt.json --pin <key>            # verdict only (exit code)
shomei-memory-verify receipt.json --render               # no --pin: refuses to certify,
                                                          #   prints "self-consistent only"
shomei-memory-verify receipt.json --pin <wrong> --render # tamper test: "VERIFICATION FAILED"
shomei-memory-verify -  --pin <key> --json               # read receipt from stdin, machine output
```

## Verify a receipt (library)

```python
from shomei_memory_verify import verify_signed_receipt, render

result = verify_signed_receipt(open("receipt.json").read())
assert result.valid          # ed25519 signature + receipt_hash both check
assert result.authenticated  # ...and it matches the key you expected

print(render(result, expected_public_key_hex="<signer_public_key_hex>"))
```

## Honest by construction

The human-readable statement (`--render`) **never strengthens a claim beyond what verification
established.** Certification language ("VERIFIED ✓", "this certifies…") is emitted only for an
*authenticated* result. A merely self-consistent (unpinned) receipt is downgraded to an explicit
"asserted, pending attribution" statement; an invalid receipt renders no certificate at all. The
explicit non-claims — what the receipt does **not** cover — are always shown verbatim.

---

© Shomei Labs. The verifier is open; the Shomei Memory engine and SDK are proprietary.
