# RAGSHIELD — RAG corpus poisoning detector — embedding anomalies, backdoor triggers

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-ragshield.svg)](https://pypi.org/project/cognis-ragshield/)
[![CI](https://github.com/cognis-digital/ragshield/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/ragshield/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**RAG corpus poisoning detector — embedding anomalies, backdoor triggers.**

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

<!-- cognis:layman:start -->
## What is this?

RAGSHIELD checks the documents stored inside an AI assistant's knowledge base for hidden attacks before they can mislead the AI. When someone poisons a knowledge base — by inserting invisible characters, sneaky instructions, or dozens of duplicate entries — the AI starts giving wrong or harmful answers to real users. RAGSHIELD scans every document and flags suspicious content, giving you a clear report with severity levels so you can remove the bad entries before they cause damage. It is designed for developers and security teams who build or maintain AI tools that rely on a searchable document library.
<!-- cognis:layman:end -->

## Why

Security and intelligence teams need RAG corpus poisoning detector — embedding anomalies, backdoor triggers without standing up heavyweight infrastructure. `ragshield` is single-purpose, scriptable, CI-friendly, and self-hostable: point it at a target, get prioritized findings in the format your workflow already speaks (table, JSON, SARIF, HTML), and wire it into agents over MCP when you want it autonomous.

<!-- cognis:install:start -->
## Install

`ragshield` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/ragshield/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/ragshield/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/ragshield.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/ragshield.git"  # uv
pip install "git+https://github.com/cognis-digital/ragshield.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/ragshield.git
cd ragshield && pip install .
```

Then run:
```sh
ragshield --help
```
<!-- cognis:install:end -->

## Install

```bash
pip install "git+https://github.com/cognis-digital/ragshield.git"
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
ragshield --version
ragshield scan demos/                      # run against the bundled demo
ragshield scan demos/ --format sarif --out r.sarif --fail-on high
ragshield scan demos/ --format html --out report.html
ragshield mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Each scenario folder includes a `SCENARIO.md` describing the situation and the findings to expect.

- [`demos/01-basic/`](demos/01-basic/SCENARIO.md)
- [`demos/01-corp-knowledge-base/`](demos/01-corp-knowledge-base/SCENARIO.md)
- [`demos/02-clean-corpus/`](demos/02-clean-corpus/SCENARIO.md)
- [`demos/03-research-papers-mixed/`](demos/03-research-papers-mixed/SCENARIO.md)

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes
- **HTML** — shareable report with severity rollups

## How it fits the Cognis Neural Suite

`ragshield` is one of **52 tools** in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `ai-security`:** [`aegis`](https://github.com/cognis-digital/aegis), [`promptmirror`](https://github.com/cognis-digital/promptmirror), [`ledgermind`](https://github.com/cognis-digital/ledgermind), [`adversa`](https://github.com/cognis-digital/adversa), [`guardpost`](https://github.com/cognis-digital/guardpost), [`hallumark`](https://github.com/cognis-digital/hallumark), [`aicard`](https://github.com/cognis-digital/aicard), [`biascope`](https://github.com/cognis-digital/biascope), [`mcpharden`](https://github.com/cognis-digital/mcpharden), [`agentlog`](https://github.com/cognis-digital/agentlog)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
