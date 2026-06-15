#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import json
import sys
import urllib.error
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Post ragshield scan results (JSON from stdin) to a webhook URL.",
    )
    ap.add_argument(
        "--url", required=True,
        help="Destination URL (must start with http:// or https://)",
    )
    ap.add_argument(
        "--header", action="append", default=[], metavar="Key: Value",
        help="Extra request header in 'Key: Value' format (may be repeated)",
    )
    ap.add_argument("--timeout", type=int, default=15,
                    help="HTTP request timeout in seconds (default: 15)")
    args = ap.parse_args()

    # validate URL scheme
    url = args.url.strip()
    if not url.lower().startswith(("http://", "https://")):
        print(f"error: --url must start with http:// or https://, got: {url!r}",
              file=sys.stderr)
        return 2

    # validate timeout
    if args.timeout <= 0:
        print(f"error: --timeout must be a positive integer, got: {args.timeout}",
              file=sys.stderr)
        return 2

    # read and validate stdin
    raw = sys.stdin.read()
    if not raw.strip():
        print(
            "error: no input on stdin — pipe ragshield scan output here",
            file=sys.stderr,
        )
        return 2
    try:
        json.loads(raw)  # validate it is parseable JSON before sending
    except json.JSONDecodeError as exc:
        print(f"error: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 2
    payload = raw.encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(f"error: malformed --header (expected 'Key: Value'), got: {h!r}",
                  file=sys.stderr)
            return 2
        k, _, v = h.partition(":")
        k = k.strip()
        v = v.strip()
        if not k:
            print(f"error: empty header name in: {h!r}", file=sys.stderr)
            return 2
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook error: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook error: {exc.reason}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
