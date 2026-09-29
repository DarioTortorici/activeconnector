"""Unit: staged-diff comparators produce minimal Add/Delete/Replace modifications."""

import pytest

module = pytest.importorskip(
    "mwa_ad_connector.application.verification.comparators",
    reason="Verification track (Step 10) has not landed yet.",
)


def test_noop_when_converged() -> None:
    """Identical current/desired yields no modifications (idempotent update)."""
    assert module.staged_diff({"mail": ["a@x"]}, {"mail": ["a@x"]}) == []


def test_add_delete_replace_semantics() -> None:
    """New values add, removed values delete, disjoint sets replace, None deletes."""
    mods = module.staged_diff({"a": ["1"], "b": ["1"], "c": ["1"]}, {"a": ["1", "2"], "b": [], "c": None, "d": ["9"]})
    by_attr = {m.attribute: (m.op, list(m.values)) for m in mods}
    assert by_attr["a"][0] == "add" and "2" in by_attr["a"][1]
    assert by_attr["b"][0] in ("delete", "replace")
    assert by_attr["c"] == ("delete", ["1"])
    assert by_attr["d"][0] == "add"


def test_absent_attributes_untouched() -> None:
    """Attributes absent from desired are left alone (partial update semantics)."""
    mods = module.staged_diff({"keep": ["1"], "chg": ["1"]}, {"chg": ["2"]})
    assert [m.attribute for m in mods] == ["chg"]
