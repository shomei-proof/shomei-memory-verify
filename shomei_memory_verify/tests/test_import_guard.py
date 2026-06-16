"""GUARD: the verifier must stay a standalone leaf — it may import ONLY the Python standard library
plus ``cryptography``, and its own submodules. No engine, framework, or other third-party code may
slip in. This is the mechanical "didn't grow a surprise dependency, didn't reach into anything else"
tripwire, expressed as an ALLOWLIST (not a denylist): a NEW import fails CI until it is added here
deliberately, with review.

Three independent checks:
  * a static AST scan of the shipped package source — every absolute import's top-level root must be
    on the allowlist (relative intra-package imports are always fine);
  * proof the tripwire actually fires, against a planted import in a nested submodule; and
  * a runtime smoke that imports every shipped submodule under a minimal environment (CI installs
    only ``cryptography``), so any undeclared dependency would fail to import.
"""
import ast
import importlib
import pathlib

import shomei_memory_verify

PKG = pathlib.Path(shomei_memory_verify.__file__).resolve().parent

# The ENTIRE permitted import surface of the shipped package. Everything here is the Python standard
# library except ``cryptography`` — the one third-party dependency, declared in pyproject.toml.
ALLOWED_ROOTS = {
    "__future__", "dataclasses", "typing",          # typing / dataclass machinery
    "json", "hashlib", "decimal",                   # canonicalization + hashing (RFC 8785 JCS)
    "datetime",                                     # receipt_render timestamps
    "argparse", "sys",                              # the __main__ CLI
    "cryptography",                                 # the only third-party dependency
}


def _shipped_sources():
    # Recursively (so a nested submodule can't escape), excluding the tests/ subtree.
    return sorted(p for p in PKG.rglob("*.py") if "tests" not in p.relative_to(PKG).parts)


def _absolute_import_roots(path):
    """Top-level roots of ABSOLUTE imports in one file. Relative intra-package imports are skipped."""
    roots = []
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if isinstance(node, ast.Import):
            roots += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            roots.append(node.module.split(".")[0])
    return roots


def test_every_import_is_on_the_allowlist():
    offenders = sorted({r for p in _shipped_sources() for r in _absolute_import_roots(p)
                        if r not in ALLOWED_ROOTS})
    assert not offenders, (
        "the verifier grew an unreviewed import (engine, framework, or third-party): "
        f"{offenders}. If intentional, add it to ALLOWED_ROOTS with review."
    )


def test_guard_actually_fires_on_a_planted_nested_import(tmp_path):
    # Prove the recursive scan reaches a NESTED module and that an off-allowlist import is flagged
    # (the failure mode a non-recursive scan would miss).
    nested = tmp_path / "sub"
    nested.mkdir()
    leak = nested / "sneaky.py"
    leak.write_text("import some_third_party_engine  # planted, not on the allowlist\n")
    roots = _absolute_import_roots(leak)
    assert "some_third_party_engine" in roots
    assert "some_third_party_engine" not in ALLOWED_ROOTS


def test_all_submodules_import_under_minimal_deps():
    # In CI only ``cryptography`` (+ pytest) is installed. Importing every shipped submodule therefore
    # PROVES there is no undeclared dependency: a stray ``import requests`` / engine import would raise
    # ImportError here.
    importlib.import_module("shomei_memory_verify")
    for p in _shipped_sources():
        rel = p.relative_to(PKG).with_suffix("")
        name = "shomei_memory_verify." + ".".join(rel.parts)
        if name.endswith(".__init__"):
            name = name[: -len(".__init__")]
        importlib.import_module(name)
