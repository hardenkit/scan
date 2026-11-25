package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/watch"
)

// minWatchInterval is the shortest --every; the data behind a scan changes
// daily, and every pass queries OSV.dev.
const minWatchInterval = 10 * time.Minute

// watcher is one configured "hardenkit watch" run.
type watcher struct {
	targets   []watchTarget
	opts      scanOptions
	alertOn   finding.Priority
	statePath string
	state     *watch.State
	webhook   string
	slack     string
	reportURL string // where reports go on a dashboard; "" when not reporting
	token     string
	host      string
	stdout    io.Writer
	stderr    io.Writer
}

// watchTarget is a target as given on the command line and the name it is
// saved and reported under.
type watchTarget struct {
	arg  string
	name string
}

func watchCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	every := fs.Duration("every", 24*time.Hour, "")
	once := fs.Bool("once", false, "")
	alertOn := fs.String("alert-on", "fix_soon", "")
	statePath := fs.String("state", "", "")
	webhook := fs.String("webhook", os.Getenv("HARDENKIT_WATCH_WEBHOOK"), "")
	slack := fs.String("slack", os.Getenv("HARDENKIT_SLACK_WEBHOOK"), "")
	reportTo := fs.String("report-to", "", "")
	project := fs.String("project", "", "")
	noNVD := fs.Bool("no-nvd", false, "")
	noDB := fs.Bool("no-db", false, "")
	noAI := fs.Bool("no-ai", false, "")
	noK8s := fs.Bool("no-k8s", false, "")
	noActions := fs.Bool("no-actions", false, "")
	images := fs.Bool("images", false, "")
	ignoreUnfixed := fs.Bool("ignore-unfixed", false, "")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *images && *noK8s {
		fmt.Fprintln(stderr, "--images needs the Kubernetes checks; drop --no-k8s")
		return exitError
	}
	if !*once && *every < minWatchInterval {
		fmt.Fprintf(stderr, "--every must be at least %s, got %s\n", minWatchInterval, *every)
		return exitError
	}
	priority, err := watch.ParsePriority(*alertOn)
	if err != nil {
		fmt.Fprintf(stderr, "--alert-on %v\n", err)
		return exitError
	}
	// Webhook URLs are secrets: say which one is wrong, never its value.
	for _, hook := range []struct{ name, value string }{{"--webhook", *webhook}, {"--slack", *slack}} {
		if hook.value != "" && !isHTTPURL(hook.value) {
			fmt.Fprintf(stderr, "%s must be an http or https URL\n", hook.name)
			return exitError
		}
	}
	var reportURL string
	token := os.Getenv("HARDENKIT_TOKEN")
	if *reportTo != "" || *project != "" {
		if *reportTo == "" || *project == "" {
			fmt.Fprintln(stderr, "--report-to and --project go together")
			return exitError
		}
		if token == "" {
			fmt.Fprintln(stderr, "--report-to needs an API key in HARDENKIT_TOKEN")
			return exitError
		}
		if reportURL, err = watch.ReportURL(*reportTo, *project); err != nil {
			fmt.Fprintf(stderr, "--report-to %v\n", err)
			return exitError
		}
	}
	if *statePath == "" {
		if *statePath, err = watch.DefaultStatePath(); err != nil {
			fmt.Fprintf(stderr, "error: no default state file (%v); set --state\n", err)
			return exitError
		}
	}
	state, err := watch.Load(*statePath)
	if err != nil {
		fmt.Fprintf(stderr, "error: read state: %v\n", err)
		return exitError
	}

	w := &watcher{
		opts: scanOptions{
			noNVD:         *noNVD,
			noDB:          *noDB,
			noAI:          *noAI,
			noK8s:         *noK8s,
			noActions:     *noActions,
			images:        *images,
			ignoreUnfixed: *ignoreUnfixed,
		},
		alertOn:   priority,
		statePath: *statePath,
		state:     state,
		webhook:   *webhook,
		slack:     *slack,
		reportURL: reportURL,
		token:     token,
		stdout:    stdout,
		stderr:    stderr,
	}
	if w.host, err = os.Hostname(); err != nil {
		w.host = "unknown"
	}
	targets := fs.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}
	seen := map[string]bool{}
	for _, t := range targets {
		name := targetName(t)
		if !seen[name] {
			seen[name] = true
			w.targets = append(w.targets, watchTarget{arg: t, name: name})
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		if failed := w.pass(ctx); failed || ctx.Err() != nil {
			return exitError
		}
		return exitOK
	}
	tick := time.NewTicker(*every)
	defer tick.Stop()
	for {
		w.pass(ctx)
		select {
		case <-ctx.Done():
			return exitOK
		case <-tick.C:
		}
	}
}

// pass scans every target once and alerts on what changed. It reports
// whether a scan, an alert or saving the state failed.
func (w *watcher) pass(ctx context.Context) (failed bool) {
	logf := func(msg string, a ...any) { fmt.Fprintf(w.stderr, msg+"\n", a...) }
	quiet := func(string, ...any) {} // scan progress is noise in an unattended run

	for _, t := range w.targets {
		if ctx.Err() != nil {
			return failed
		}
		result, err := runScan(ctx, t.arg, w.opts, quiet)
		if ctx.Err() != nil {
			return failed // interrupted: the result may be incomplete
		}
		if err != nil {
			// The previous state stays, so nothing is reported as resolved.
			logf("error: scan %s: %v", t.name, err)
			failed = true
			continue
		}
		for _, warning := range result.Warnings {
			logf("warning: %s: %s", t.name, warning)
		}

		current := watch.FromScan(result.Findings)
		now := time.Now().UTC().Truncate(time.Second)

		// The dashboard gets every scan, changed or not, so it can tell a
		// quiet server from one that stopped reporting.
		if w.reportURL != "" {
			report, truncated := watch.NewReport(version, w.host, t.name, now, result.Packages, result.Findings)
			if truncated > 0 {
				logf("warning: %s: the report holds the %d most urgent findings; %d were left out", t.name, len(report.Findings), truncated)
			}
			if err := watch.SendReport(ctx, w.reportURL, w.token, report); err != nil {
				logf("error: report for %s: %v", t.name, err)
				failed = true
			}
		}

		change := watch.Diff(w.state.Targets[t.name], current, w.alertOn)
		change.Host, change.Target, change.Time = w.host, t.name, now

		if change.Alert() {
			fmt.Fprintf(w.stdout, "%s\n", change.Text())
			sent := true
			if w.webhook != "" {
				if err := watch.SendWebhook(ctx, w.webhook, change); err != nil {
					logf("error: webhook for %s: %v", t.name, err)
					sent = false
				}
			}
			if w.slack != "" {
				if err := watch.SendSlack(ctx, w.slack, change); err != nil {
					logf("error: Slack message for %s: %v", t.name, err)
					sent = false
				}
			}
			if !sent {
				// Keep the old state so the next pass alerts again.
				failed = true
				continue
			}
		} else {
			what := "nothing changed"
			if change.FirstRun {
				what = "first run, nothing"
			}
			fmt.Fprintf(w.stdout, "%s: %s at or above %s (%s)", t.name, what, w.alertOn, change.Summary)
			if n := len(change.Resolved); n > 0 {
				fmt.Fprintf(w.stdout, "; %d resolved", n)
			}
			fmt.Fprintln(w.stdout)
		}

		w.state.Targets[t.name] = &watch.Target{Checked: now, Findings: current}
		if err := w.state.Save(w.statePath); err != nil {
			logf("error: save state: %v", err)
			failed = true
		}
	}
	return failed
}

// targetName is the name a target is saved and reported under: the absolute
// path for a directory or file, so "." means the same thing wherever the
// command runs, and the reference itself for a container image.
func targetName(target string) string {
	if path := localPath(target); path != "" {
		if abs, err := filepath.Abs(path); err == nil {
			return abs
		}
	}
	return target
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}
