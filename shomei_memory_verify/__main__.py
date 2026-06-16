"""CLI: independently verify a Shomei Memory receipt and optionally render a human-readable statement.

    python -m shomei_memory_verify receipt.json --pin <hex>             # verify, print one-line status
    python -m shomei_memory_verify receipt.json --pin <hex> --render    # + a GC/DPO/regulator one-pager
    python -m shomei_memory_verify receipt.json --json                  # machine-readable result

Exit code is 0 ONLY when the receipt is AUTHENTICATED against the pinned key (a real trust pass); a
self-consistent-but-unpinned or invalid receipt exits non-zero, so scripts can gate on it.
"""
from __future__ import annotations

import argparse
import json
import sys

from .receipt_render import render
from .verify import verify_signed_receipt


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="shomei_memory_verify",
                                 description="Independently verify a Shomei Memory signed receipt, offline.")
    ap.add_argument("receipt", help="path to the signed-receipt JSON ('-' reads stdin)")
    ap.add_argument("--pin", "--expected-public-key", dest="pin", metavar="HEX", default=None,
                    help="the signer's public key (hex), obtained out-of-band, to AUTHENTICATE against")
    ap.add_argument("--render", action="store_true",
                    help="emit a plain-language statement for a GC / DPO / regulator")
    ap.add_argument("--json", action="store_true", help="emit the structured verification result as JSON")
    a = ap.parse_args(argv)

    raw = sys.stdin.read() if a.receipt == "-" else open(a.receipt, encoding="utf-8").read()
    r = verify_signed_receipt(json.loads(raw), expected_public_key_hex=a.pin)

    if a.render:
        print(render(r))
    elif a.json:
        print(json.dumps({"valid": r.valid, "authenticated": r.authenticated, "reason": r.reason,
                          "schema": r.schema, "public_key_hex": r.public_key_hex}, indent=2))
    else:
        print(f"valid={r.valid} authenticated={r.authenticated} reason={r.reason} schema={r.schema}")
        if r.valid and not r.authenticated:
            sys.stderr.write("note: pass --pin <signer_public_key_hex> to AUTHENTICATE (unpinned proves no authorship)\n")
    return 0 if r.authenticated else 1


if __name__ == "__main__":
    raise SystemExit(main())
