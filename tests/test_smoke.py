"""Smoke tests for RAGSHIELD - import the engine and run it on the demo corpus.

No network access. Run with: python -m pytest tests/  (or python tests/test_smoke.py)
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ragshield import (
    TOOL_NAME,
    TOOL_VERSION,
    load_jsonl,
    scan_corpus,
    detect_backdoor_triggers,
    detect_instruction_injection,
    detect_embedding_anomalies,
    detect_duplication,
)
from ragshield.cli import main

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "corpus.jsonl")


def test_metadata():
    assert TOOL_NAME == "ragshield"
    assert TOOL_VERSION.count(".") == 2


def test_loads_demo_corpus():
    docs = load_jsonl(DEMO)
    assert len(docs) == 14
    assert all("id" in d and "text" in d for d in docs)


def test_scan_flags_poison():
    docs = load_jsonl(DEMO)
    result = scan_corpus(docs)
    assert result.doc_count == 14
    assert result.poisoned is True
    assert result.risk_score > 0
    flagged = {f.doc_id for f in result.findings}
    # each planted attack must be caught
    assert "poison-1" in flagged   # instruction injection
    assert "poison-2" in flagged   # zero-width trigger
    assert "poison-3" in flagged   # rare repeated token
    assert "poison-4" in flagged   # embedding norm outlier
    # duplication flood: one representative finding covers the cluster
    dup = [f for f in result.findings if f.detector == "duplication"]
    assert dup and dup[0].evidence.get("count", 0) >= 5


def test_clean_docs_not_flagged():
    docs = load_jsonl(DEMO)
    result = scan_corpus(docs)
    flagged = {f.doc_id for f in result.findings}
    for clean in ("kb-1", "kb-2", "kb-3", "kb-4", "kb-5"):
        assert clean not in flagged, f"{clean} should be clean"


def test_individual_detectors():
    docs = load_jsonl(DEMO)
    assert any(f.doc_id == "poison-1" for f in detect_instruction_injection(docs))
    bd = detect_backdoor_triggers(docs)
    assert any(f.doc_id == "poison-2" for f in bd)
    assert any(f.doc_id == "poison-3" for f in bd)
    assert any(f.doc_id == "poison-4" for f in detect_embedding_anomalies(docs))
    assert any(f.detector == "duplication" for f in detect_duplication(docs))


def test_no_findings_on_clean_corpus():
    clean = [
        {"id": "a", "text": "The library opens at nine in the morning on weekdays."},
        {"id": "b", "text": "Tickets can be purchased online or at the front desk."},
        {"id": "c", "text": "Parking is available in the rear lot for two hours free."},
    ]
    result = scan_corpus(clean)
    assert result.findings == []
    assert result.poisoned is False


def test_cli_exit_code_nonzero_on_poison():
    rc = main(["scan", DEMO, "--format", "json"])
    assert rc == 1


def test_cli_version_zero_exit():
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0


if __name__ == "__main__":
    test_metadata()
    test_loads_demo_corpus()
    test_scan_flags_poison()
    test_clean_docs_not_flagged()
    test_individual_detectors()
    test_no_findings_on_clean_corpus()
    test_cli_exit_code_nonzero_on_poison()
    test_cli_version_zero_exit()
    print("all smoke tests passed")
