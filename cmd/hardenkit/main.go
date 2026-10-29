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
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hardenkit/scan/internal/aistack"
	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/httpx"
	"github.com/hardenkit/scan/internal/inventory"
	"github.com/hardenkit/scan/internal/issue"
	"github.com/hardenkit/scan/internal/kube"
	"github.com/hardenkit/scan/internal/osv"
	"github.com/hardenkit/scan/internal/report"
	"github.com/hardenkit/scan/internal/vulndb"
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
  --format FORMAT      text (default), json, or markdown (for CI summaries)
  --fail-on LEVEL      exit 1 if any finding is at or above LEVEL:
                       kev, critical, high, medium, low (default: never fail).
                       AI-stack and Kubernetes issues count too, except
                       for kev
  --ignore-unfixed     leave out vulnerabilities that have no fixed version
                       yet (exploited ones are always kept)
  --no-db              don't use the prebuilt database; query KEV, EPSS and
                       NVD live (slow without an NVD API key)
  --no-nvd             skip live CVSS lookups from NVD
  --no-ai              skip the AI-stack checks (MCP configs, model files,
                       risky model-loading code)
  --no-k8s             skip the Kubernetes manifest and Helm chart checks
  --images             also scan every container image the Kubernetes
                       manifests deploy (pulled from their registries)
  --summary-file PATH  also append a Markdown report to PATH (e.g.
                       "$GITHUB_STEP_SUMMARY")
  -v, --verbose        show summaries, file locations and advisory links

The AI-stack checks list LLM SDKs, agent frameworks, vector databases, MCP
servers and model files, and flag secrets and unpinned servers in MCP
configs, model files that run code when loaded, and code such as
trust_remote_code=True.

The Kubernetes checks read manifests and Helm charts (rendered with "helm
template" when helm is installed) and flag privileged pods, host access,
gaps against the restricted Pod Security Standard, broad RBAC and committed
Secrets.

Severity scores, exploitation data (CISA KEV) and exploit likelihood (EPSS)
come from a prebuilt database that is updated daily and cached locally.

Environment:
  HARDENKIT_DB_URL        database location: an https URL or a local file
  HARDENKIT_NVD_API_KEY   NVD API key for live lookups; raises the NVD rate
                          limit from 5 to 50 requests per 30 seconds

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
	noDB := fs.Bool("no-db", false, "")
	noAI := fs.Bool("no-ai", false, "")
	noK8s := fs.Bool("no-k8s", false, "")
	images := fs.Bool("images", false, "")
	ignoreUnfixed := fs.Bool("ignore-unfixed", false, "")
	summaryFile := fs.String("summary-file", "", "")
	verbose := fs.Bool("verbose", false, "")
	fs.BoolVar(verbose, "v", false, "")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *images && *noK8s {
		fmt.Fprintln(stderr, "--images needs the Kubernetes checks; drop --no-k8s")
		return exitError
	}
	if *format != "text" && *format != "json" && *format != "markdown" {
		fmt.Fprintf(stderr, "--format must be text, json or markdown, got %q\n", *format)
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

	result := report.Result{Target: target, Sources: []string{"OSV.dev"}}
	warn := func(msg string, a ...any) {
		result.Warnings = append(result.Warnings, fmt.Sprintf(msg, a...))
	}

	// Something that is clearly a path but doesn't exist would otherwise be
	// tried as an image reference and fail with every provider's error.
	if looksLikePath(target) {
		if _, err := os.Stat(target); err != nil {
			logf("error: %v", err)
			return exitError
		}
	}

	logf("Cataloging packages in %s ...", target)
	pkgs, err := inventory.Collect(ctx, target)
	if err != nil {
		logf("error: %v", err)
		return exitError
	}

	// Kubernetes runs before matching so --images can add the packages of
	// every image the manifests deploy.
	if path := localPath(target); path != "" && !*noK8s {
		k, err := kube.Scan(ctx, path)
		if err != nil {
			warn("Kubernetes checks failed: %v", err)
		} else if k != nil {
			logf("Checked %d Kubernetes resources ...", len(k.Resources))
			result.Kubernetes = k
			result.Warnings = append(result.Warnings, k.Warnings...)
		}
	}
	if *images {
		if result.Kubernetes == nil || len(result.Kubernetes.Images) == 0 {
			warn("--images: no container images found in Kubernetes manifests")
		} else {
			got, failed, firstErr := collectImages(ctx, result.Kubernetes.Images, logf)
			pkgs = append(pkgs, got...)
			if len(failed) > 0 {
				hint := ""
				for _, img := range failed {
					if !strings.Contains(img, "/") {
						hint = ` Bare names such as "` + img + `" are usually placeholders a build tool (skaffold, kustomize) replaces.`
						break
					}
				}
				warn("could not pull %d of %d images: %s (first error: %s).%s",
					len(failed), len(result.Kubernetes.Images), strings.Join(failed, ", "), firstErr, hint)
			}
		}
	}

	var targets []osv.Target
	seen := map[string]bool{}
	for _, p := range pkgs {
		if p.PURL == "" || p.Version == "" {
			continue
		}
		t := osv.TargetFor(p.PURL, p.Name, p.Version)
		if !seen[t.Key] {
			seen[t.Key] = true
			targets = append(targets, t)
		}
	}

	logf("Matching %d packages against OSV.dev ...", len(targets))
	matches, err := osv.Query(ctx, targets)
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

	result.Packages = len(pkgs)

	// Enrichment makes the ranking better but is not required for a result,
	// so a failing source becomes a warning instead of failing the scan.
	var (
		kev  map[string]enrich.KEVEntry
		epss map[string]float64
		cvss map[string]enrich.CVSS
		live = len(cves) > 0
	)
	if len(cves) > 0 && !*noDB {
		src := os.Getenv("HARDENKIT_DB_URL")
		if src == "" {
			src = vulndb.DefaultURL
		}
		logf("Loading vulnerability database ...")
		db, w, err := vulndb.Load(ctx, src)
		if w != "" {
			warn("%s", w)
		}
		if err != nil {
			warn("prebuilt vulnerability database unavailable (%v); used live data sources", err)
		} else {
			live = false
			kev, epss, cvss = db.Lookup(cves)
			result.Sources = append(result.Sources, "CISA KEV", "FIRST EPSS", "NVD")
			result.Database = db.Generated

			// CVEs published since the nightly build have no score yet; look
			// those few up live when that's quick.
			var missing []string
			for _, id := range cves {
				if _, ok := cvss[id]; !ok {
					missing = append(missing, id)
				}
			}
			key := os.Getenv("HARDENKIT_NVD_API_KEY")
			if len(missing) > 0 && !*noNVD && (key != "" || len(missing) <= 5) {
				logf("Fetching CVSS scores from NVD for %d CVEs newer than the database ...", len(missing))
				extra, err := enrich.NVD(ctx, missing, key)
				if err != nil {
					warn("%v", err)
				}
				for id, c := range extra {
					cvss[id] = c
				}
			}
		}
	}
	if live {
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

		key := os.Getenv("HARDENKIT_NVD_API_KEY")
		if !*noNVD && key == "" && len(cves) > 10 {
			// Keyless NVD allows one request every 6 seconds; don't stall the scan.
			warn("skipped NVD CVSS scores for %d CVEs: live lookups without HARDENKIT_NVD_API_KEY would take about %d minutes", len(cves), (len(cves)*6+59)/60)
		} else if !*noNVD {
			logf("Fetching CVSS scores from NVD ...")
			if cvss, err = enrich.NVD(ctx, cves, key); err != nil {
				warn("%v", err)
			}
			if len(cvss) > 0 {
				result.Sources = append(result.Sources, "NVD")
			}
		}
	}

	result.Findings = finding.Build(pkgs, matches, vulns, kev, epss, cvss)
	if *ignoreUnfixed {
		kept := result.Findings[:0]
		for _, f := range result.Findings {
			// Exploited vulnerabilities stay: they need a mitigation even without a fix.
			if f.FixedIn != "" || f.KEV != nil {
				kept = append(kept, f)
			} else {
				result.Unfixed++
			}
		}
		result.Findings = kept
	}
	if result.Findings == nil {
		result.Findings = []finding.Finding{}
	}
	result.Upgrades = finding.UpgradePlan(result.Findings)
	if result.Upgrades == nil {
		result.Upgrades = []finding.Upgrade{}
	}

	if !*noAI {
		ai := aistack.New()
		// Config, model and code checks need files on disk, so they don't
		// run on container images; the package inventory works for both.
		if path := localPath(target); path != "" {
			logf("Checking AI stack ...")
			if ai, err = aistack.Scan(ctx, path); err != nil {
				warn("AI-stack checks failed: %v", err)
				ai = aistack.New()
			}
		}
		ai.Components = aistack.Components(pkgs)
		result.AIStack = ai
	}

	switch *format {
	case "json":
		err = report.JSON(stdout, result)
	case "markdown":
		err = report.Markdown(stdout, result)
	default:
		err = report.Text(stdout, result, *verbose)
	}
	if err != nil {
		logf("error: %v", err)
		return exitError
	}
	if *summaryFile != "" {
		if err := appendMarkdown(*summaryFile, result); err != nil {
			logf("error: write summary: %v", err)
			return exitError
		}
	}
	if ctx.Err() != nil {
		return exitError
	}

	if threshold != "" && failed(result, threshold) {
		logf("\nFailing: findings at or above %s (--fail-on).", strings.ToLower(threshold))
		return exitFindings
	}
	return exitOK
}

// appendMarkdown appends a Markdown report to path; GitHub's step summary
// file is shared by every step, so it must be appended to, not replaced.
func appendMarkdown(path string, r report.Result) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := report.Markdown(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func failed(r report.Result, threshold string) bool {
	for _, f := range r.Findings {
		if f.KEV != nil {
			return true // exploited vulnerabilities fail every threshold
		}
		if threshold != "KEV" && finding.AtLeast(f.Severity, threshold) {
			return true
		}
	}
	if threshold == "KEV" {
		return false
	}
	var issues []issue.Issue
	if r.AIStack != nil {
		issues = append(issues, r.AIStack.Issues...)
	}
	if r.Kubernetes != nil {
		issues = append(issues, r.Kubernetes.Issues...)
	}
	for _, is := range issues {
		if finding.AtLeast(is.Severity, threshold) {
			return true
		}
	}
	return false
}

// imageWorkers is how many images are pulled and cataloged at once.
const imageWorkers = 4

// collectImages catalogs each image and tags its packages with the image
// reference. It also returns the images that couldn't be pulled and the
// first of their errors.
func collectImages(ctx context.Context, images []string, logf func(string, ...any)) ([]inventory.Package, []string, string) {
	type result struct {
		pkgs []inventory.Package
		err  error
	}
	results := make([]result, len(images))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < imageWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				logf("Cataloging image %s ...", images[i])
				pkgs, err := inventory.CollectImage(ctx, images[i])
				for j := range pkgs {
					pkgs[j].Image = images[i]
				}
				results[i] = result{pkgs, err}
			}
		}()
	}
	for i := range images {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	var pkgs []inventory.Package
	var failed []string
	var firstErr string
	for i, r := range results {
		if r.err != nil {
			failed = append(failed, images[i])
			if firstErr == "" {
				firstErr = lastLine(r.err.Error())
			}
			continue
		}
		pkgs = append(pkgs, r.pkgs...)
	}
	return pkgs, failed, firstErr
}

// lastLine returns the most specific line of a multi-line error, trimmed.
func lastLine(msg string) string {
	lines := strings.Split(strings.TrimSpace(msg), "\n")
	line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[len(lines)-1]), "-"))
	if len(line) > 160 {
		line = line[:160] + "..."
	}
	return line
}

func looksLikePath(target string) bool {
	for _, prefix := range []string{"/", "./", "../", "~", ".\\", "..\\"} {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return target == "." || target == ".." || filepath.VolumeName(target) != ""
}

// localPath returns the directory or file a target names, or "" when the
// target is a container image. Syft's "dir:" and "file:" prefixes are allowed.
func localPath(target string) string {
	for _, prefix := range []string{"dir:", "file:"} {
		if p, ok := strings.CutPrefix(target, prefix); ok {
			return p
		}
	}
	if _, err := os.Stat(target); err == nil {
		return target
	}
	return ""
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
