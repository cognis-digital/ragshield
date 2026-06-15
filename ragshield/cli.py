"""RAGSHIELD command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import load_jsonl, scan_corpus, ScanResult

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _render_table(result: ScanResult, path: str) -> str:
    lines: List[str] = []
    lines.append(f"RAGSHIELD scan: {path}")
    lines.append(f"documents: {result.doc_count}   risk_score: {result.risk_score:.1f}   "
                 f"poisoned: {'YES' if result.poisoned else 'no'}")
    counts = result.severity_counts()
    summary = "  ".join(f"{k}={counts[k]}" for k in ("critical", "high", "medium", "low", "info"))
    lines.append("severity: " + summary)
    lines.append("-" * 72)
    if not result.findings:
        lines.append("No poisoning indicators found.")
        return "\n".join(lines)
    lines.append(f"{'SEV':<5} {'DETECTOR':<22} {'DOC':<14} MESSAGE")
    for f in result.findings:
        doc = f.doc_id if len(f.doc_id) <= 14 else f.doc_id[:11] + "..."
        lines.append(f"{_SEV_LABEL.get(f.severity, f.severity):<5} "
                     f"{f.detector:<22} {doc:<14} {f.message}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="RAGSHIELD - detect poisoning, backdoor triggers and "
                    "embedding anomalies in a RAG corpus (JSONL).",
        epilog="example: ragshield scan demos/01-basic/corpus.jsonl --format table",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a JSONL corpus file for poisoning")
    scan.add_argument("corpus", help="path to the JSONL corpus file")
    scan.add_argument("--format", choices=["table", "json"], default="table",
                      help="output format (default: table)")
    scan.add_argument("--dup-threshold", type=float, default=0.9,
                      help="near-duplicate Jaccard threshold (default: 0.9)")
    scan.add_argument("--fail-on", choices=["medium", "high", "critical", "any", "never"],
                      default="medium",
                      help="minimum severity that causes a non-zero exit "
                           "(default: medium)")
    return parser


def _should_fail(result: ScanResult, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if fail_on == "any":
        return bool(result.findings)
    order = {"critical": 0, "high": 1, "medium": 2}
    cutoff = order[fail_on]
    return any(order.get(f.severity, 99) <= cutoff for f in result.findings)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None) or args.command != "scan":
        parser.print_help()
        return 0

    # validate --dup-threshold range before touching the file
    dup_threshold = args.dup_threshold
    if not (0.0 < dup_threshold <= 1.0):
        print(
            f"error: --dup-threshold must be in range (0.0, 1.0], got {dup_threshold}",
            file=sys.stderr,
        )
        return 2

    try:
        docs = load_jsonl(args.corpus)
    except FileNotFoundError:
        print(f"error: corpus not found: {args.corpus}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(
            f"error: corpus path is a directory, not a file: {args.corpus}",
            file=sys.stderr,
        )
        return 2
    except PermissionError:
        print(
            f"error: permission denied reading corpus: {args.corpus}",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(f"error: could not read corpus: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        result = scan_corpus(docs, dup_threshold=dup_threshold)
    except (TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_render_table(result, args.corpus))

    return 1 if _should_fail(result, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
