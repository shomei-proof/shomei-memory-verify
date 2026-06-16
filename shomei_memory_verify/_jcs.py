#!/usr/bin/env python3
"""RFC 8785 JSON Canonicalization Scheme (JCS) — the receipt wire-contract canonicalizer.

The published open verifier and the governed engine canonicalize receipt bodies with RFC 8785 JCS,
not Python's ``json.dumps(sort_keys=True)``, so a third party re-canonicalizing in ANY language or
library computes the same bytes (hence the same hash and the same signature input). This module is
dependency-free (stdlib only) so the standalone verifier can vendor a byte-identical copy without
pulling in any engine code.

Existing signed fixtures whose bodies are ASCII-keyed and free of fractional/large floats remain
byte-transparent under JCS; payloads that would diverge from I-JSON fail closed instead of being
signed or verified under an ambiguous encoding. The ECMAScript Number::toString (RFC 8785 §3.2.2.3)
is implemented via exact ``Decimal`` arithmetic — the standard reference technique, and the part to
verify hardest.

What JCS specifies (RFC 8785):
  * §3.2.2.2 strings  — escape " \\ and C0 controls (\\b \\t \\n \\f \\r short forms; else \\u00xx lowercase);
                        everything else emitted as raw UTF-8. No \\uXXXX for non-ASCII.
  * §3.2.2.3 numbers  — ECMAScript Number::toString. NaN/Infinity MUST be rejected.
  * §3.2.3   objects  — member keys sorted by UTF-16 code units (NOT Unicode code point).
  * Input MUST be well-formed Unicode (lone surrogates rejected) and I-JSON (no duplicate keys upstream).

Canon policy decisions encoded here (fail-closed, conservative for a forever-frozen contract):
  * non-finite floats (NaN/Inf) -> reject (RFC 8785 mandate; also fixes the old sort_keys non-conformance).
  * lone surrogates -> reject (RFC 8785 well-formed-Unicode requirement).
  * non-string object keys -> reject (JSON keys are strings; a python int key is a latent order bug).
  * integers outside JS safe-integer range (|x| > 2**53 - 1) -> reject (beyond it, JSON-number == IEEE-754
    double semantics are ambiguous; carry such values as strings). Small receipt ints are unaffected.
"""
from __future__ import annotations

from decimal import Decimal

_MAX_SAFE_INT = 2 ** 53 - 1
_MAX_DEPTH = 64  # fail-closed on pathological nesting (a verifier must not DoS via RecursionError)

# RFC 8785 §3.2.2.2 short escapes for the C0 controls that have them.
_SHORT_ESCAPE = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
}


class JcsError(ValueError):
    """RFC 8785 canonicalization could not proceed (rejected, not merely different)."""


def _number(value) -> str:
    """ECMAScript Number::toString (ECMA-262 §7.1.12.1) as mandated by RFC 8785 §3.2.2.3."""
    if isinstance(value, bool):  # bool is an int subclass — must be handled at the value level, never here
        raise JcsError("bool routed to _number")
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise JcsError(f"integer {value} exceeds JS safe-integer range; encode as a string")
        return str(value)
    # float
    if value != value or value in (float("inf"), float("-inf")):
        raise JcsError("non-finite number (NaN/Infinity) is not valid JSON / RFC 8785")
    if value == 0:
        return "0"  # collapses 0.0 and -0.0
    neg = value < 0
    # repr() gives the shortest decimal that round-trips; Decimal parses it exactly; normalize() strips trailing
    # zeros so the digit tuple is the minimal significand the ECMAScript algorithm assumes.
    d = Decimal(repr(abs(value))).normalize()
    _sign, digits, exp = d.as_tuple()
    digits_str = "".join(str(x) for x in digits)
    k = len(digits_str)          # number of significant digits
    n = exp + k                  # ECMA: value = s * 10**(n-k); decimal point sits after position n
    if k <= n <= 21:
        s = digits_str + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits_str[:n] + "." + digits_str[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits_str
    else:
        e = n - 1
        esign = "+" if e >= 0 else "-"
        mant = digits_str if k == 1 else digits_str[0] + "." + digits_str[1:]
        s = f"{mant}e{esign}{abs(e)}"
    return ("-" + s) if neg else s


def _string(value: str) -> str:
    out = ['"']
    for ch in value:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JcsError("lone surrogate in string; input is not well-formed Unicode")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o in _SHORT_ESCAPE:
            out.append(_SHORT_ESCAPE[o])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)  # raw; emitted as UTF-8 at the end
    out.append('"')
    return "".join(out)


def _serialize(value, depth: int = 0) -> str:
    if depth > _MAX_DEPTH:
        raise JcsError(f"maximum nesting depth ({_MAX_DEPTH}) exceeded")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise JcsError(f"object key {k!r} is not a string")
            for ch in k:  # validate keys BEFORE the utf-16-be sort, so a lone-surrogate key fails closed
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise JcsError("lone surrogate in object key; not well-formed Unicode")
        # RFC 8785 §3.2.3: sort by UTF-16 code units. Encoding to utf-16-be (2 bytes/unit, MSB-first) is
        # order-equivalent to comparing the 16-bit code-unit arrays.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _serialize(v, depth + 1) for k, v in items) + "}"
    raise JcsError(f"type {type(value).__name__} is not JSON-serializable under JCS")


def canonicalize(value) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of ``value``. Raises JcsError on non-canonicalizable input."""
    return _serialize(value).encode("utf-8")


# --------------------------------------------------------------------------------------------- self-test vectors
# (label, value, expected canonical string). Number cases cross-checked against ECMAScript Number::toString.
_VECTORS = [
    ("int", 1, "1"),
    ("float_one", 1.0, "1"),
    ("zero", 0.0, "0"),
    ("neg_zero", -0.0, "0"),
    ("lr_002", 0.02, "0.02"),
    ("int_valued_100", 100.0, "100"),
    ("epoch_ms", 1700000000000.0, "1700000000000"),
    ("e16", 1e16, "10000000000000000"),
    ("e21", 1e21, "1e+21"),
    ("e_minus7", 1e-7, "1e-7"),
    ("tenth", 0.1, "0.1"),
    ("three_quarters", 0.75, "0.75"),
    ("neg", -3.5, "-3.5"),
    ("str_plain", "abc", '"abc"'),
    ("str_unicode_raw", "René😀", '"René😀"'),
    ("str_escapes", 'a"b\\c\n\t', '"a\\"b\\\\c\\n\\t"'),
    ("str_ctrl", "\x00\x1f", '"\\u0000\\u001f"'),
    ("obj_sort", {"b": 1, "a": 2}, '{"a":2,"b":1}'),
    # astral emoji (U+1F600 -> surrogate D83D…) sorts BEFORE the BMP private-use U+E000 under UTF-16
    # code units, though by Unicode CODE POINT the emoji is higher — the exact JCS-vs-sort_keys divergence.
    # Escapes are explicit so an invisible char can't silently corrupt the vector.
    ("obj_utf16_keysort", {"\U0001F600": 1, "\ue000": 2}, '{"\U0001F600":1,"\ue000":2}'),
    ("nested", {"z": [1, 2], "a": {"y": 1.0}}, '{"a":{"y":1},"z":[1,2]}'),
    ("bool_null", {"t": True, "n": None}, '{"n":null,"t":true}'),
]


def _deep(n):  # n-deep nested list, to exercise the depth guard
    v = 0
    for _ in range(n):
        v = [v]
    return v


_REJECT = [
    ("nan", float("nan")),
    ("inf", float("inf")),
    ("lone_surrogate", "\ud83d"),
    ("lone_surrogate_key", {"\ud83d": 1}),
    ("int_key", {1: "a"}),
    ("huge_int", 2 ** 53 + 1),
    ("deep_nesting", _deep(_MAX_DEPTH + 5)),
]


def self_test() -> int:
    fails = []
    for label, value, expected in _VECTORS:
        try:
            got = canonicalize(value).decode("utf-8")
        except Exception as e:  # noqa: BLE001
            fails.append(f"{label}: raised {e!r} (expected {expected!r})")
            continue
        if got != expected:
            fails.append(f"{label}: got {got!r} expected {expected!r}")
    for label, value in _REJECT:
        try:
            canonicalize(value)
            fails.append(f"{label}: accepted, expected JcsError")
        except JcsError:
            pass
        except Exception as e:  # noqa: BLE001
            fails.append(f"{label}: raised {type(e).__name__}, expected JcsError")
    if fails:
        print("JCS SELF-TEST FAILURES:")
        for f in fails:
            print("  ", f)
        return 1
    print(f"JCS self-test PASS — {len(_VECTORS)} canonical vectors + {len(_REJECT)} reject cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test())
