"""Render a verified Shomei Memory receipt into a plain-language statement a GC / DPO / regulator can read.

The cryptographic receipt is machine-checkable but opaque to humans. This produces a one-page statement:
what is certified, the basis, the explicit scope, the honest NON-CLAIMS, and a "verify it yourself"
appendix. It lives in the VERIFIER (not the engine) on purpose: a human-readable claim is only credible
if it is the OUTPUT of an independent verification, not operator prose.

INTEGRITY RULE: the prose NEVER strengthens a claim beyond what verification
established. Certification language is emitted ONLY for an AUTHENTICATED result (a pinned key); a merely
self-consistent (unpinned) receipt is downgraded to an explicit "asserted, not yet attributed" statement,
and an invalid receipt renders no certificate at all. The non-claims are emitted VERBATIM regardless.
"""
from __future__ import annotations

import datetime
from typing import Any, Mapping, Union

from .receipt import SignedReceipt
from .verify import VerifyResult, verify_signed_receipt

# --- honest non-claims, emitted verbatim for every receipt of the given family ----------------------
_NC_STORE = [
    "This covers ONLY this governed memory store. It does NOT assert removal from anything the data was "
    "copied or derived into elsewhere — model training, analytics warehouses, logs, caches, backups kept "
    "outside this store, or third-party systems.",
    "It does NOT assert that facts about the subject still inferable from OTHER, correlated records are gone.",
    "The subject is named by a one-way PSEUDONYM, not erased to anonymity: a holder of the tenant key can "
    "re-derive it to PROVE completeness — pseudonymized-with-proof, not unlinkable-anonymized.",
    "It attests the at-rest state AT THE STATED TIME; the current state is re-established by the auditor "
    "recompute below (a backup-restore is caught and re-erased on open by the off-volume no-resurrection ledger).",
]


def _ts(v: Any) -> str:
    try:
        return datetime.datetime.utcfromtimestamp(float(v)).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return "<unknown time>"


def _pid(s: Any) -> str:
    s = str(s or "")
    return (s.split(":")[-1][:16] + "…") if s else "<none>"


def _status_block(r: VerifyResult):
    """(headline, established, advisory_line). `established` gates all certification language."""
    if r.authenticated:
        return ("VERIFIED ✓", True,
                "The ed25519 signature was checked, offline, against the public key you pinned. "
                "The statement below is established by that check, not asserted by the operator.")
    if r.valid:
        return ("SELF-CONSISTENT ONLY — NOT independently attributed", False,
                "This receipt is internally consistent, but you did NOT pin the signer's public key, so it "
                "does not prove WHO produced it — anyone could have signed it with their own key. Obtain "
                "the signer's key out-of-band and re-verify before relying on anything below.")
    return ("NOT A VALID RECEIPT", False,
            f"Verification FAILED (reason: {r.reason}). The signature or hash did not check, or the receipt "
            f"is malformed. Do NOT rely on this document.")


def _closure(b: Mapping[str, Any], established: bool):
    disp = b.get("disposition")
    human = {
        "complete": "COMPLETE — every matched record was erased",
        "deferred": "DEFERRED — erasure is held under a legal hold and AUTO-FIRES on release (the records "
                    "are already withheld from use in the meantime)",
        "partial": "PARTIAL — some matched records erased, some still pending",
        "noop_no_match": "NO MATCH — no records were found for this subject",
    }.get(disp, str(disp))
    verb = "have been erased from" if established else "are ASSERTED (pending the verification above) to have been erased from"
    certify = (
        f"The personal records of the subject with pseudonym `{_pid(b.get('subject_pseudonym'))}` {verb} the "
        f"governed memory store. Of **{b.get('matched_count','?')}** record(s) matched for this subject, "
        f"**{b.get('erased_count','?')}** were cryptographically erased and **{b.get('deferred_count','?')}** "
        f"deferred. **Disposition: {human}.** Effective {_ts(b.get('applied_at'))}.")
    basis = [
        "- **Crypto-erasure, not a flag flip:** each record's content was sealed under its own key; erasure "
        "DESTROYS that key, so the ciphertext is permanently undecryptable — including in backups (the "
        "off-volume no-resurrection ledger re-erases any restored copy on open).",
        "- **Per-record proof:** each erasure also emits its own content-free, ed25519-signed receipt.",
        "- **Auditor-reproducible set:** `closed_set_commitment` is a keyed commitment over the at-rest erased "
        "set that an auditor RECOMPUTES and byte-compares — the operator cannot understate the set.",
    ]
    scope = f"The tenant's governed memory store (per-tenant encrypted database). Match basis: `{b.get('match_basis','?')}`."
    return "Right-to-be-Forgotten — Subject Closure Certificate", certify, basis, scope, _NC_STORE


def _delete(b: Mapping[str, Any], established: bool):
    verb = "was cryptographically erased" if established else "is ASSERTED (pending the verification above) to have been erased"
    certify = (
        f"Memory record `{b.get('memory_id','?')}` {verb} from the governed memory store: its content "
        f"encryption key was destroyed, so the stored ciphertext is permanently undecryptable. "
        f"Key custody: **{b.get('key_custody','?')}**. Physical-purge state: {b.get('physical_purge_state','?')}. "
        f"Its vector representation was revoked in the same transaction.")
    basis = [
        "- **Crypto-erasure:** the per-record key was destroyed (not merely a tombstone), so even a copy of "
        "the ciphertext cannot be decrypted.",
        "- **Tombstone:** a content-free deletion tombstone (`tombstone_id`) records the erasure for audit.",
    ]
    scope = "A single record in the tenant's governed memory store."
    return "Record Deletion Receipt", certify, basis, scope, _NC_STORE


def _restrict(b: Mapping[str, Any], established: bool):
    applied = b.get("action") == "applied" or b.get("restricted_state") is True
    if applied:
        certify = (f"Memory record `{b.get('memory_id','?')}` has been **RESTRICTED** (GDPR Art.18): it is "
                   f"preserved but withheld from use and recall (reason: `{b.get('reason_code','?')}`), effective "
                   f"{_ts(b.get('applied_at'))}. Restriction is reversible and non-destructive.")
    else:
        certify = (f"The processing restriction on record `{b.get('memory_id','?')}` has been **LIFTED** "
                   f"(reason: `{b.get('reason_code','?')}`), effective {_ts(b.get('applied_at'))}; the record "
                   f"returns to normal use.")
    if not established:
        certify = "ASSERTED (pending the verification above): " + certify
    basis = ["- Restriction takes the record OUT OF RECALL at the index level (not just a facade filter); it "
             "is preserved intact and remains reachable only for audit / legal access."]
    scope = "A single record in the tenant's governed memory store."
    nc = ["This is RESTRICTION (out-of-use), NOT erasure — the record is preserved and reversible.",
          "It covers ONLY this governed memory store, not copies/derivations elsewhere."]
    return "Processing-Restriction Notice (GDPR Art.18)", certify, basis, scope, nc


_RENDERERS = {
    "shomei.subject_closure.v1": _closure,
    "shomei.vector_delete.v1": _delete,
    "shomei.restriction.v1": _restrict,
}


def render(receipt: Union[VerifyResult, SignedReceipt, Mapping[str, Any]],
           *, expected_public_key_hex: str = None) -> str:
    """Render a Shomei receipt into a plain-language statement. Accepts a VerifyResult, a SignedReceipt, or
    a parsed-JSON mapping; if not already verified, it verifies first (pass ``expected_public_key_hex`` to
    pin the signer — without it the statement is honestly downgraded to 'self-consistent only')."""
    r = receipt if isinstance(receipt, VerifyResult) else \
        verify_signed_receipt(receipt, expected_public_key_hex=expected_public_key_hex)
    headline, established, advisory = _status_block(r)
    b, schema = r.body, r.schema

    L = ["**Verification status:** " + headline, "", advisory, ""]
    if not r.valid:
        # An invalid receipt is never dressed up as a certificate.
        L = ["# Shomei Memory Receipt — VERIFICATION FAILED", ""] + L
        L += ["---", f"*Appendix: schema=`{schema or '<unsigned>'}`; reason=`{r.reason}`; "
              f"signer_public_key=`{(r.public_key_hex or '')[:24]}…`.*"]
        return "\n".join(L)

    fn = _RENDERERS.get(schema)
    if fn is None:
        title = f"Shomei Memory Receipt — `{schema or 'unknown type'}`"
        certify = ("A human-readable summary for this receipt type is not available, but its cryptographic "
                   "verification (above) still applies. The signed contents are in the appendix.")
        basis, scope, nclaims = [], "The tenant's governed memory store.", _NC_STORE[:1]
    else:
        title, certify, basis, scope, nclaims = fn(b, established)

    out = ["# " + title, ""] + L
    out += ["## What this certifies" if established else "## What this receipt ASSERTS (verification incomplete — see status)",
            certify, ""]
    if basis:
        out += ["## Basis (you do not have to trust the operator)"] + basis + [""]
    out += ["## Scope", scope, "",
            "## What this does NOT claim (read carefully)"] + [f"- {nc}" for nc in nclaims] + [""]
    out += ["## How to verify this yourself (offline, trusting no one)",
            "Using only this receipt file and the signer's public key (obtained out-of-band):", "",
            "```", f"python -m shomei_memory_verify receipt.json --pin <signer_public_key_hex> --render", "```", ""]
    pk = (r.public_key_hex or "")
    out += ["---",
            f"*Cryptographic appendix (for the technical verifier): schema=`{schema}`; "
            f"signer_public_key=`{pk[:24]}…`; signer_id(advisory)=`{r.signer_id}`; "
            + "; ".join(f"{k}=`{str(b[k])[:30]}…`" for k in ("tenant_id_hash", "closed_set_commitment", "tombstone_id")
                        if k in b) + ".*"]
    return "\n".join(out)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline(s: str) -> str:
    """Minimal inline markdown -> HTML for the render() subset: **bold**, `code`, *italic*. Escapes first."""
    s = _esc(s)
    out, i, n = [], 0, len(s)
    while i < n:
        if s.startswith("**", i):
            j = s.find("**", i + 2)
            if j != -1:
                out.append("<strong>" + s[i + 2:j] + "</strong>"); i = j + 2; continue
        if s[i] == "`":
            j = s.find("`", i + 1)
            if j != -1:
                out.append("<code>" + s[i + 1:j] + "</code>"); i = j + 1; continue
        if s[i] == "*":
            j = s.find("*", i + 1)
            if j != -1:
                out.append("<em>" + s[i + 1:j] + "</em>"); i = j + 1; continue
        out.append(s[i]); i += 1
    return "".join(out)


_CSS = ("body{font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:46rem;margin:2rem "
        "auto;padding:0 1rem;color:#1a1a1a}h1{font-size:1.5rem}h2{font-size:1.05rem;margin-top:1.4rem;"
        "border-bottom:1px solid #eee;padding-bottom:.2rem}code{background:#f3f3f3;padding:.1em .3em;"
        "border-radius:3px;font-size:.85em}pre{background:#f6f8fa;padding:.8rem;border-radius:6px;overflow:auto}"
        "hr{border:none;border-top:1px solid #ddd;margin:1.5rem 0}em{color:#555}"
        ".op{background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:.6rem .8rem;font-size:.9em}")


def to_html(markdown: str, *, operator_note: str = None) -> str:
    """Render the render() markdown into a styled, standalone, PRINTABLE html document (a GC prints it to
    PDF for filing). Pure presentation — the markdown remains the canonical, auditor-reproducible artifact.
    ``operator_note`` adds an honest banner when the OPERATOR produced this (vs an independent verifier)."""
    body, in_ul, in_pre = [], False, False
    if operator_note:
        body.append(f'<div class="op">{_inline(operator_note)}</div>')
    for line in markdown.split("\n"):
        if line.strip() == "```":
            body.append("<pre>" if not in_pre else "</pre>"); in_pre = not in_pre; continue
        if in_pre:
            body.append(_esc(line)); continue
        if line.startswith("- "):
            if not in_ul: body.append("<ul>"); in_ul = True
            body.append("<li>" + _inline(line[2:]) + "</li>"); continue
        if in_ul: body.append("</ul>"); in_ul = False
        if line.startswith("## "): body.append("<h2>" + _inline(line[3:]) + "</h2>")
        elif line.startswith("# "): body.append("<h1>" + _inline(line[2:]) + "</h1>")
        elif line.strip() == "---": body.append("<hr>")
        elif line.strip() == "": body.append("")
        else: body.append("<p>" + _inline(line) + "</p>")
    if in_ul: body.append("</ul>")
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>Shomei Memory Receipt</title>"
            f"<style>{_CSS}</style></head><body>\n" + "\n".join(body) + "\n</body></html>")


__all__ = ["render", "to_html"]
