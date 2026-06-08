# RAGSHIELD — RAG corpus poisoning detector — embedding anomalies, backdoor triggers

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-ragshield.svg)](https://pypi.org/project/cognis-ragshield/)
[![CI](https://github.com/cognis-digital/ragshield/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/ragshield/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

RAG corpus poisoning detector — embedding anomalies, backdoor triggers.

## Install

```bash
pip install cognis-ragshield
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
ragshield --version
ragshield scan demos/                          # run against bundled demo
ragshield scan demos/ --format sarif --out r.sarif --fail-on high
ragshield mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-corp-knowledge-base/` — see [`SCENARIO.md`](demos/01-corp-knowledge-base/SCENARIO.md)
- `demos/02-clean-corpus/` — see [`SCENARIO.md`](demos/02-clean-corpus/SCENARIO.md)
- `demos/03-research-papers-mixed/` — see [`SCENARIO.md`](demos/03-research-papers-mixed/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
