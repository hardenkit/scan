// Command hardenkit finds the vulnerabilities that matter in a project,
// container image or filesystem.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/httpx"
	"github.com/hardenkit/scan/internal/inventory"
	"github.com/hardenkit/scan/internal/osv"
	"github.com/hardenkit/scan/internal/report"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes, so CI can tell "vulnerable" apart from "broken".
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

const usage = `hardenkit finds the vulnerabilities that matter in your dependencies and containers.

Usage:
  hardenkit scan [flags] [target]

Target is a directory (default "."), a file, or a container image such as
"alpine:3.19" or "registry:ghcr.io/org/app:latest".

Flags:
  --format text|json   output format (default text)
  --fail-on LEVEL      exit 1 if any finding is at or above LEVEL:
                       kev, critical, high, medium, low (default: never fail)
  --no-nvd             skip CVSS scores from NVD (faster without an API key)
  -v, --verbose        show summaries, file locations and advisory links

Environment:
  HARDENKIT_NVD_API_KEY   NVD API key; raises the NVD rate limit from 5 to 50
                          requests per 30 seconds

Other commands:
  hardenkit version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	httpx.UserAgent = fmt.Sprintf("hardenkit-scan/%s (+https://hardenkit.com)", version)

	switch args[0] {
	case "scan":
		return scan(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "hardenkit", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return exitError
	}
}

func scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	format := fs.String("format", "text", "")
	failOn := fs.String("fail-on", "", "")
	noNVD := fs.Bool("no-nvd", false, "")
	verbose := fs.Bool("verbose", false, "")
	fs.BoolVar(verbose, "v", false, "")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "--format must be text or json, got %q\n", *format)
		return exitError
	}
	threshold := strings.ToUpper(*failOn)
	switch threshold {
	case "", "KEV", "CRITICAL", "HIGH", "MEDIUM", "LOW":
	default:
		fmt.Fprintf(stderr, "--fail-on must be kev, critical, high, medium or low, got %q\n", *failOn)
		return exitError
	}
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Progress and errors go to stderr so stdout stays clean for --format json.
	logf := func(msg string, a ...any) { fmt.Fprintf(stderr, msg+"\n", a...) }

	logf("Cataloging packages in %s ...", target)
	pkgs, err := inventory.Collect(ctx, target)
	if err != nil {
		logf("error: %v", err)
		return exitError
	}

	var purls []string
	seen := map[string]bool{}
	for _, p := range pkgs {
		if p.PURL == "" || p.Version == "" {
			continue
		}
		n := osv.NormalizePURL(p.PURL)
		if !seen[n] {
			seen[n] = true
			purls = append(purls, n)
		}
	}

	logf("Matching %d packages against OSV.dev ...", len(purls))
	matches, err := osv.Query(ctx, purls)
	if err != nil {
		logf("error: %v", err)
		return exitError
	}
	idSet := map[string]bool{}
	for _, ids := range matches {
		for _, id := range ids {
			idSet[id] = true
		}
	}
	ids := keys(idSet)
	vulns, err := osv.Fetch(ctx, ids)
	if err != nil {
		logf("error: %v", err)
		return exitError
	}

	cveSet := map[string]bool{}
	for _, v := range vulns {
		if c := v.CVE(); c != "" {
			cveSet[c] = true
		}
	}
	cves := keys(cveSet)

	result := report.Result{Target: target, Packages: len(pkgs), Sources: []string{"OSV.dev"}}
	warn := func(msg string, a ...any) {
		result.Warnings = append(result.Warnings, fmt.Sprintf(msg, a...))
	}

	// Enrichment makes the ranking better but is not required for a result,
	// so a failing source becomes a warning instead of failing the scan.
	var (
		kev  map[string]enrich.KEVEntry
		epss map[string]float64
		cvss map[string]enrich.CVSS
	)
	if len(cves) > 0 {
		logf("Checking %d CVEs against CISA KEV and EPSS ...", len(cves))
		if kev, err = enrich.KEV(ctx); err != nil {
			warn("%v", err)
		} else {
			result.Sources = append(result.Sources, "CISA KEV")
		}
		if epss, err = enrich.EPSS(ctx, cves); err != nil {
			warn("%v", err)
		} else {
			result.Sources = append(result.Sources, "FIRST EPSS")
		}

		if !*noNVD {
			key := os.Getenv("HARDENKIT_NVD_API_KEY")
			if key == "" && len(cves) > 10 {
				logf("Fetching CVSS scores from NVD for %d CVEs without an API key; this takes about %d seconds (set HARDENKIT_NVD_API_KEY or pass --no-nvd).", len(cves), len(cves)*6)
			} else {
				logf("Fetching CVSS scores from NVD ...")
			}
			if cvss, err = enrich.NVD(ctx, cves, key); err != nil {
				warn("%v", err)
			}
			if len(cvss) > 0 {
				result.Sources = append(result.Sources, "NVD")
			}
		}
	}

	result.Findings = finding.Build(pkgs, matches, vulns, kev, epss, cvss)
	if result.Findings == nil {
		result.Findings = []finding.Finding{}
	}
	result.Upgrades = finding.UpgradePlan(result.Findings)
	if result.Upgrades == nil {
		result.Upgrades = []finding.Upgrade{}
	}

	if *format == "json" {
		err = report.JSON(stdout, result)
	} else {
		err = report.Text(stdout, result, *verbose)
	}
	if err != nil {
		logf("error: %v", err)
		return exitError
	}
	if ctx.Err() != nil {
		return exitError
	}

	if threshold != "" && failed(result.Findings, threshold) {
		logf("\nFailing: findings at or above %s (--fail-on).", strings.ToLower(threshold))
		return exitFindings
	}
	return exitOK
}

func failed(fs []finding.Finding, threshold string) bool {
	for _, f := range fs {
		if f.KEV != nil {
			return true // exploited vulnerabilities fail every threshold
		}
		if threshold != "KEV" && finding.AtLeast(f.Severity, threshold) {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
