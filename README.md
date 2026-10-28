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

> Status: early development. Not yet released.

## Usage

```bash
hardenkit scan                      # scan the current directory
hardenkit scan ./path/to/project    # scan a directory
hardenkit scan alpine:3.19          # scan a container image
hardenkit scan --format json .      # machine-readable output
hardenkit scan --fail-on high .     # exit 1 on high/critical or exploited findings (for CI)
hardenkit scan -v .                 # include summaries, file locations and advisory links
```

Exit codes: `0` no failing findings, `1` findings at or above `--fail-on`, `2` the scan itself failed.

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
