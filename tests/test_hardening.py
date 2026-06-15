"""Hardening tests for RAGSHIELD — error paths, edge cases, bad input.

Covers:
  - CLI: missing file -> exit 2 with stderr message
  - CLI: corpus is a directory -> exit 2
  - CLI: --dup-threshold out of range -> exit 2
  - CLI: malformed JSONL -> exit 2
  - core: scan_corpus with empty list -> zero findings, not poisoned
  - core: scan_corpus with non-list docs -> TypeError
  - core: scan_corpus with invalid dup_threshold -> ValueError
  - core: load_jsonl on a directory -> IsADirectoryError
  - core: load_jsonl on malformed JSONL -> ValueError with line number
  - core: detectors are no-ops on empty corpus
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ragshield.core import (
    detect_backdoor_triggers,
    detect_duplication,
    detect_embedding_anomalies,
    detect_instruction_injection,
    load_jsonl,
    scan_corpus,
)
from ragshield.cli import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jsonl(lines: list, suffix: str = ".jsonl") -> str:
    """Write lines (str or dict) to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write((json.dumps(line) if isinstance(line, dict) else line) + "\n")
    return path


# ---------------------------------------------------------------------------
# CLI hardening tests
# ---------------------------------------------------------------------------

def test_cli_missing_file_returns_exit_2(capsys):
    rc = main(["scan", "/nonexistent/path/corpus.jsonl"])
    assert rc == 2
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()
    assert "corpus" in captured.err.lower() or "not found" in captured.err.lower()


def test_cli_corpus_is_directory_returns_exit_2(tmp_path, capsys):
    rc = main(["scan", str(tmp_path)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()


def test_cli_dup_threshold_too_low_returns_exit_2(capsys):
    # 0.0 is out of range (must be > 0.0)
    path = _make_jsonl([{"id": "a", "text": "hello world this is a test"}])
    try:
        rc = main(["scan", path, "--dup-threshold", "0.0"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()
    finally:
        os.unlink(path)


def test_cli_dup_threshold_above_1_returns_exit_2(capsys):
    path = _make_jsonl([{"id": "a", "text": "hello world this is a test"}])
    try:
        rc = main(["scan", path, "--dup-threshold", "1.5"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()
    finally:
        os.unlink(path)


def test_cli_malformed_jsonl_returns_exit_2(capsys):
    path = _make_jsonl(["not valid json !!!"])
    try:
        rc = main(["scan", path])
        assert rc == 2
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()
    finally:
        os.unlink(path)


def test_cli_no_command_prints_help_and_returns_0(capsys):
    rc = main([])
    assert rc == 0


def test_cli_clean_corpus_returns_exit_0():
    path = _make_jsonl([
        {"id": "x1", "text": "Clean document number one about databases."},
        {"id": "x2", "text": "Another clean document about file systems."},
        {"id": "x3", "text": "A third document about network protocols."},
    ])
    try:
        rc = main(["scan", path, "--fail-on", "medium"])
        assert rc == 0
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# core.load_jsonl hardening tests
# ---------------------------------------------------------------------------

def test_load_jsonl_directory_raises(tmp_path):
    with pytest.raises(IsADirectoryError):
        load_jsonl(str(tmp_path))


def test_load_jsonl_malformed_line_raises_value_error():
    path = _make_jsonl(["not json at all"])
    try:
        with pytest.raises(ValueError, match=r"line 1|invalid JSON"):
            load_jsonl(path)
    finally:
        os.unlink(path)


def test_load_jsonl_non_object_line_raises_value_error():
    path = _make_jsonl(["[1, 2, 3]"])
    try:
        with pytest.raises(ValueError, match=r"expected a JSON object"):
            load_jsonl(path)
    finally:
        os.unlink(path)


def test_load_jsonl_empty_file_returns_empty_list(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    docs = load_jsonl(str(empty))
    assert docs == []


def test_load_jsonl_skips_blank_lines():
    path = _make_jsonl([
        {"id": "a", "text": "first"},
        "",
        "",
        {"id": "b", "text": "second"},
    ])
    try:
        docs = load_jsonl(path)
        assert len(docs) == 2
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# core.scan_corpus hardening tests
# ---------------------------------------------------------------------------

def test_scan_corpus_empty_list_is_clean():
    result = scan_corpus([])
    assert result.findings == []
    assert result.doc_count == 0
    assert result.poisoned is False
    assert result.risk_score == 0.0


def test_scan_corpus_non_list_raises_type_error():
    with pytest.raises(TypeError, match="list"):
        scan_corpus({"id": "a", "text": "hello"})  # type: ignore[arg-type]


def test_scan_corpus_threshold_zero_raises_value_error():
    with pytest.raises(ValueError, match="dup_threshold"):
        scan_corpus([], dup_threshold=0.0)


def test_scan_corpus_threshold_negative_raises_value_error():
    with pytest.raises(ValueError, match="dup_threshold"):
        scan_corpus([], dup_threshold=-0.1)


def test_scan_corpus_threshold_above_1_raises_value_error():
    with pytest.raises(ValueError, match="dup_threshold"):
        scan_corpus([], dup_threshold=1.1)


def test_scan_corpus_threshold_exactly_1_is_valid():
    result = scan_corpus([], dup_threshold=1.0)
    assert result.findings == []


# ---------------------------------------------------------------------------
# Detector edge-case tests
# ---------------------------------------------------------------------------

def test_detectors_all_return_empty_on_empty_corpus():
    assert detect_backdoor_triggers([]) == []
    assert detect_instruction_injection([]) == []
    assert detect_embedding_anomalies([]) == []
    assert detect_duplication([]) == []


def test_detectors_handle_missing_text_field():
    docs = [{"id": "no-text-doc"}]
    # Should not raise; treat missing text as empty string
    assert detect_backdoor_triggers(docs) == []
    assert detect_instruction_injection(docs) == []
    assert detect_duplication(docs) == []


def test_detectors_handle_none_text():
    docs = [{"id": "null-text", "text": None}]
    assert detect_backdoor_triggers(docs) == []
    assert detect_instruction_injection(docs) == []


def test_embedding_anomaly_skips_non_list_embedding():
    docs = [{"id": "bad-emb", "text": "hello", "embedding": "not a list"}]
    # should not raise; non-list embedding is silently skipped (< 4 vecs)
    result = detect_embedding_anomalies(docs)
    assert result == []


def test_embedding_anomaly_flags_non_numeric():
    docs = [
        {"id": f"d{i}", "text": "t", "embedding": [float(i), float(i + 1)]}
        for i in range(4)
    ] + [{"id": "bad", "text": "x", "embedding": ["not", "a", "number"]}]
    findings = detect_embedding_anomalies(docs)
    bad = [f for f in findings if f.doc_id == "bad"]
    assert bad, "non-numeric embedding should produce a finding"
    assert bad[0].severity == "low"


def test_scan_result_severity_counts_all_zeros_on_empty():
    from ragshield.core import ScanResult
    sr = ScanResult()
    counts = sr.severity_counts()
    assert all(v == 0 for v in counts.values())
