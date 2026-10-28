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

### NVD API key (optional)

CVSS scores come from the [National Vulnerability Database](https://nvd.nist.gov/developers/request-an-api-key). Without a key NVD allows 5 requests per 30 seconds, which makes large scans slow. With a key it's 50.

```bash
export HARDENKIT_NVD_API_KEY=your-key   # or pass --no-nvd to skip CVSS scores
```

## What it checks

Packages are found with [Syft](https://github.com/anchore/syft), which covers npm, PyPI, Go, Maven, Cargo, RubyGems, NuGet, Composer, and Linux distribution packages (Debian, Alpine, RPM) in container images.

| Source | Used for |
|:-------|:---------|
| [OSV.dev](https://osv.dev) | Matching package versions to vulnerabilities, and fixed versions |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities exploited in the wild |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days |
| [NVD](https://nvd.nist.gov) | CVSS scores |

## Build

Requires Go (see `go.mod` for the version).

```bash
make build    # bin/hardenkit
make check    # vet, tests, formatting
```

## License

Apache-2.0. Built by [HardenKit](https://hardenkit.com).
