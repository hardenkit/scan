# hardenkit scan

Find the vulnerabilities that matter in your dependencies and containers, and the one upgrade that fixes them.

Most scanners hand you a list of hundreds of CVEs. `hardenkit scan` ranks them by what attackers are actually doing:

| Priority | Meaning |
|:---------|:--------|
| **FIX NOW** | Being exploited in the wild (on CISA's Known Exploited Vulnerabilities list) |
| **FIX SOON** | Critical, or likely to be exploited in the next 30 days (EPSS ≥ 10%) |
| **PLAN** | High severity |
| **BACKLOG** | Everything else |

Then it collapses them into an **upgrade plan**: one line per package with the single version that resolves every fixable finding.

It also checks your **AI stack**: the LLM SDKs, agent frameworks, vector databases, MCP servers and model files in the project, and the settings that let one of them take over a machine.

> Status: early development. Not yet released.

## Usage

```bash
hardenkit scan                      # scan the current directory
hardenkit scan ./path/to/project    # scan a directory
hardenkit scan alpine:3.19          # scan a container image
hardenkit scan --format json .      # machine-readable output
hardenkit scan --fail-on high .     # exit 1 on high/critical or exploited findings (for CI)
hardenkit scan -v .                 # include summaries, file locations and advisory links
hardenkit scan --no-ai .            # skip the AI-stack checks
```

Exit codes: `0` no failing findings, `1` findings at or above `--fail-on`, `2` the scan itself failed. AI-stack issues count toward `--fail-on` at their severity, except with `--fail-on kev`, which only fails on exploited vulnerabilities.

## Install

```bash
curl -sSfL https://hardenkit.sh | sh
```

Or download a build for your platform from [Releases](https://github.com/hardenkit/scan/releases).

## GitHub Action

```yaml
- uses: actions/checkout@v7
- uses: hardenkit/scan@v0
  with:
    fail-on: high        # kev, critical, high, medium, low, or "" to never fail
    # target: .          # directory, file, or container image
    # args: --verbose
```

The upgrade plan and findings appear in the job summary. The step fails when a finding is at or above `fail-on`; vulnerabilities exploited in the wild (CISA KEV) always fail it.

### Vulnerability database

Severity scores (NVD CVSS), exploitation data (CISA KEV) and exploit likelihood (EPSS) for every CVE are rebuilt every night and published as a small download. The CLI fetches it once a day and caches it, so scans take seconds and need no API keys. Package matching itself always queries OSV.dev live.

If the database can't be downloaded, the CLI falls back to querying those sources live. `--no-db` forces that. For live NVD lookups an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) raises the rate limit from 5 to 50 requests per 30 seconds:

```bash
export HARDENKIT_NVD_API_KEY=your-key
```

`HARDENKIT_DB_URL` points the CLI at a different database (an https URL or a local file), for example a mirror inside an air-gapped network.

## What it checks

Packages are found with [Syft](https://github.com/anchore/syft), which covers npm, PyPI, Go, Maven, Cargo, RubyGems, NuGet, Composer, and Linux distribution packages (Debian, Alpine, RPM) in container images.

| Source | Used for |
|:-------|:---------|
| [OSV.dev](https://osv.dev) | Matching package versions to vulnerabilities, and fixed versions |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities exploited in the wild |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days |
| [NVD](https://nvd.nist.gov) | CVSS scores |

### AI stack

The scan lists the AI parts of the project (LLM APIs, agent frameworks, vector databases, ML frameworks, MCP SDKs, MCP servers and model files) and flags:

| Check | Severity | What it finds |
|:------|:---------|:--------------|
| `model-code-execution` | Critical | Pickle-based model files (`.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.joblib`) that import `os`, `subprocess`, `eval` and similar, so loading them runs code. Files are parsed, never loaded. |
| `mcp-hardcoded-secret` | High | API keys and tokens written into MCP configs (`env`, `headers`, arguments, URLs) instead of referenced from the environment |
| `mcp-insecure-transport` | High | Remote MCP servers over plain `http://` |
| `mcp-unsafe-container` | High | MCP servers run with `--privileged`, host networking, the Docker socket or the host root mounted |
| `mcp-remote-script` | High | MCP servers started with `curl ... \| sh` |
| `code-dangerous-deserialization` | High | `allow_dangerous_deserialization=True` (LangChain) |
| `model-keras-lambda` | High / Medium | Keras models with Lambda layers, which run embedded Python |
| `mcp-unpinned-package` | Medium | MCP servers run through `npx`, `uvx`, `pipx` or `docker` without a pinned version, or with `@latest` |
| `code-trust-remote-code` | Medium | `trust_remote_code=True` (Hugging Face Transformers) |
| `code-unsafe-torch-load` | Medium | `torch.load(..., weights_only=False)` |
| `model-unverified` | Medium | Pickle model files that couldn't be fully parsed |
| `model-pickle-format` | Low | Other pickle-based model files; safetensors can't run code |

MCP configs are read from `.mcp.json` (Claude Code), `.cursor/mcp.json`, `.vscode/mcp.json`, `mcp_config.json` (Windsurf), `claude_desktop_config.json` and `.gemini/settings.json`. Secrets are never printed. Config, model and code checks run on directories and files; for container images only the package inventory is reported.

## Attribution

This product uses the NVD API but is not endorsed or certified by the NVD. EPSS scores are provided by [FIRST](https://www.first.org/epss/). Known exploited vulnerabilities come from [CISA's KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Vulnerability matching uses [OSV.dev](https://osv.dev).

## Build

Requires Go (see `go.mod` for the version).

```bash
make build    # bin/hardenkit
go run ./cmd/vulndb-build --window 72h --out db.json.gz   # small test database
make check    # vet, tests, formatting
```

## License

Apache-2.0. Built by [HardenKit](https://hardenkit.com).
