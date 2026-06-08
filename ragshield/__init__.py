"""RAGSHIELD - RAG corpus poisoning detector.

Scans a retrieval-augmented-generation corpus (a JSONL file of documents)
for signs of poisoning / backdoor injection BEFORE the documents are
embedded and indexed. It uses only the Python standard library.

Detection signals (no embedding model required):
  * embedding anomalies      - if precomputed embedding vectors are present,
                               flags vectors that are statistical outliers
                               (per-dimension robust z-score) or have an
                               abnormal norm (a classic poisoning trick is a
                               vector pushed to the edge of the space so it
                               is retrieved for almost any query).
  * backdoor triggers        - rare repeated tokens / invisible-unicode /
                               zero-width / homoglyph payloads that act as
                               retrieval triggers.
  * instruction injection    - imperative "ignore previous instructions"
                               style payloads embedded in retrievable text.
  * duplication flooding      - many near-identical documents (a corpus is
                               poisoned by flooding it with copies so the
                               attacker's text dominates retrieval).

The engine is importable; the CLI wraps it.
"""

from .core import (
    Finding,
    ScanResult,
    scan_corpus,
    load_jsonl,
    detect_backdoor_triggers,
    detect_instruction_injection,
    detect_embedding_anomalies,
    detect_duplication,
)

TOOL_NAME = "ragshield"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "ScanResult",
    "scan_corpus",
    "load_jsonl",
    "detect_backdoor_triggers",
    "detect_instruction_injection",
    "detect_embedding_anomalies",
    "detect_duplication",
]
