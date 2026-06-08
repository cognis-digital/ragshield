"""RAGSHIELD command-line interface."""
from cognis_core import build_cli
from ragshield.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="RAG corpus poisoning detector — embedding anomalies, backdoor triggers",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
