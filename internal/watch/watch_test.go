package watch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/inventory"
)

func f(id, pkg string, p finding.Priority) Finding {
	return Finding{ID: id, Package: pkg, Version: "1.0.0", FixedIn: "1.0.1", Priority: p, Severity: "HIGH"}
}

func ids(fs []Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestDiffFirstRun(t *testing.T) {
	cur := []Finding{
		f("CVE-1", "a", finding.FixNow),
		f("CVE-2", "a", finding.FixSoon),
		f("CVE-3", "a", finding.Plan),
		f("CVE-4", "a", finding.Backlog),
	}
	c := Diff(nil, cur, finding.FixSoon)
	if !c.FirstRun || !c.Alert() {
		t.Fatalf("FirstRun = %v, Alert = %v; want both true", c.FirstRun, c.Alert())
	}
	if got := ids(c.New); !reflect.DeepEqual(got, []string{"CVE-1", "CVE-2"}) {
		t.Errorf("new = %v, want the two findings at or above FIX SOON", got)
	}
	if len(c.Raised) != 0 || len(c.Resolved) != 0 {
		t.Errorf("raised = %v, resolved = %v; want none", c.Raised, c.Resolved)
	}
	if want := (Summary{FixNow: 1, FixSoon: 1, Plan: 1, Backlog: 1}); c.Summary != want {
		t.Errorf("summary = %+v, want %+v", c.Summary, want)
	}
}

func TestDiffFirstRunNothingToAlert(t *testing.T) {
	c := Diff(nil, []Finding{f("CVE-3", "a", finding.Plan)}, finding.FixSoon)
	if !c.FirstRun || c.Alert() {
		t.Errorf("FirstRun = %v, Alert = %v; want true, false", c.FirstRun, c.Alert())
	}
}

func TestDiffNothingChanged(t *testing.T) {
	cur := []Finding{f("CVE-1", "a", finding.FixNow), f("CVE-3", "a", finding.Plan)}
	c := Diff(&Target{Findings: cur}, cur, finding.FixSoon)
	if c.FirstRun || c.Alert() || len(c.Resolved) != 0 {
		t.Errorf("change = %+v, want nothing", c)
	}
}

func TestDiffNew(t *testing.T) {
	prev := &Target{Findings: []Finding{f("CVE-1", "a", finding.FixNow)}}
	other := f("CVE-1", "a", finding.FixSoon)
	other.Version = "2.0.0" // same CVE and package, another version: a new finding
	inImage := f("CVE-1", "a", finding.FixSoon)
	inImage.Image = "app:1" // and the same in an image
	cur := []Finding{
		f("CVE-1", "a", finding.FixNow),
		f("CVE-2", "b", finding.FixSoon),
		other,
		inImage,
		f("CVE-5", "b", finding.Plan), // new, but below the alert priority
	}
	c := Diff(prev, cur, finding.FixSoon)
	if !c.Alert() || c.FirstRun {
		t.Fatalf("Alert = %v, FirstRun = %v; want true, false", c.Alert(), c.FirstRun)
	}
	if got := ids(c.New); !reflect.DeepEqual(got, []string{"CVE-2", "CVE-1", "CVE-1"}) {
		t.Errorf("new = %v", got)
	}
	if len(c.Raised) != 0 {
		t.Errorf("raised = %v, want none", c.Raised)
	}
}

func TestDiffRaised(t *testing.T) {
	prev := &Target{Findings: []Finding{
		f("CVE-1", "a", finding.Plan),    // below the alert priority, now exploited
		f("CVE-2", "a", finding.FixSoon), // already alerting, now more urgent
		f("CVE-3", "a", finding.FixNow),  // less urgent now: not raised
		f("CVE-4", "a", finding.Backlog), // more urgent, but still below
	}}
	cur := []Finding{
		f("CVE-1", "a", finding.FixNow),
		f("CVE-2", "a", finding.FixNow),
		f("CVE-3", "a", finding.FixSoon),
		f("CVE-4", "a", finding.Plan),
	}
	c := Diff(prev, cur, finding.FixSoon)
	if got := ids(c.Raised); !reflect.DeepEqual(got, []string{"CVE-1", "CVE-2"}) {
		t.Fatalf("raised = %v, want CVE-1 and CVE-2", got)
	}
	if p := c.Raised[0].PreviousPriority; p == nil || *p != finding.Plan {
		t.Errorf("previous priority = %v, want PLAN", p)
	}
	if len(c.New) != 0 || !c.Alert() {
		t.Errorf("new = %v, Alert = %v; want none, true", c.New, c.Alert())
	}
}

func TestDiffResolvedDoesNotAlert(t *testing.T) {
	prev := &Target{Findings: []Finding{
		f("CVE-1", "a", finding.FixNow),
		f("CVE-2", "a", finding.FixSoon),
		f("CVE-3", "a", finding.Backlog), // was never alerted on
	}}
	c := Diff(prev, []Finding{f("CVE-1", "a", finding.FixNow)}, finding.FixSoon)
	if c.Alert() {
		t.Error("resolved findings alone must not alert")
	}
	if got := ids(c.Resolved); !reflect.DeepEqual(got, []string{"CVE-2"}) {
		t.Errorf("resolved = %v, want CVE-2", got)
	}
}

func TestDiffAlertOnBacklog(t *testing.T) {
	c := Diff(&Target{}, []Finding{f("CVE-4", "a", finding.Backlog)}, finding.Backlog)
	if got := ids(c.New); !reflect.DeepEqual(got, []string{"CVE-4"}) {
		t.Errorf("new = %v, want CVE-4", got)
	}
}

func TestFromScan(t *testing.T) {
	epss := 0.5
	pkg := inventory.Package{Name: "openssl", Version: "3.1.4", Image: "app:1"}
	got := FromScan([]finding.Finding{
		{ID: "CVE-1", Package: pkg, FixedIn: "3.1.8", Priority: finding.FixNow, Severity: "HIGH", KEV: &enrich.KEVEntry{}, EPSS: &epss},
		{ID: "CVE-1", Package: pkg, FixedIn: "3.1.8", Priority: finding.FixNow, Severity: "HIGH", KEV: &enrich.KEVEntry{}, EPSS: &epss},
		{ID: "CVE-2", Package: pkg, Priority: finding.Backlog, Severity: "LOW"},
	})
	want := []Finding{
		{ID: "CVE-1", Package: "openssl", Version: "3.1.4", Image: "app:1", FixedIn: "3.1.8", Priority: finding.FixNow, Severity: "HIGH", KEV: true, EPSS: &epss},
		{ID: "CVE-2", Package: "openssl", Version: "3.1.4", Image: "app:1", Priority: finding.Backlog, Severity: "LOW"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromScan = %+v, want %+v", got, want)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "hardenkit", "watch.json")

	empty, err := Load(path)
	if err != nil || len(empty.Targets) != 0 {
		t.Fatalf("Load of a missing file = %+v, %v; want an empty state", empty, err)
	}

	epss := 0.42
	exploited := f("CVE-1", "a", finding.FixNow)
	exploited.KEV, exploited.EPSS, exploited.Image = true, &epss, "app:1"
	empty.Targets["/srv/app"] = &Target{
		Checked:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Findings: []Finding{exploited, f("CVE-2", "b", finding.Backlog)},
	}
	if err := empty.Save(path); err != nil {
		t.Fatal(err)
	}
	// A second save replaces the file.
	if err := empty.Save(path); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, empty) {
		t.Errorf("loaded %+v, saved %+v", got.Targets["/srv/app"], empty.Targets["/srv/app"])
	}

	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("state file mode = %o, want 600", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
			t.Errorf("state directory mode = %o, want 700", info.Mode().Perm())
		}
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".watch-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestLoadRejectsBadState(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"broken.json":  `{"version":1,"targets":`,
		"version.json": `{"version":2,"targets":{}}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load(%s) succeeded, want an error", name)
		}
	}
}

func TestDefaultStatePath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", filepath.FromSlash("/var/state"))
	if got, _ := DefaultStatePath(); got != filepath.FromSlash("/var/state/hardenkit/watch.json") {
		t.Errorf("with XDG_STATE_HOME: %s", got)
	}
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", filepath.FromSlash("/home/ops"))
	t.Setenv("USERPROFILE", filepath.FromSlash("/home/ops"))
	if got, _ := DefaultStatePath(); got != filepath.FromSlash("/home/ops/.local/state/hardenkit/watch.json") {
		t.Errorf("without XDG_STATE_HOME: %s", got)
	}
}

// sample is a change with one finding of each kind.
func sample() Change {
	epss := 0.9321
	exploited := Finding{ID: "CVE-2023-44487", Package: "golang.org/x/net", Version: "0.1.0", FixedIn: "0.17.0",
		Priority: finding.FixNow, Severity: "MEDIUM", KEV: true, EPSS: &epss}
	raised := f("CVE-2", "django", finding.FixSoon)
	prev := &Target{Findings: []Finding{
		f("CVE-2", "django", finding.Plan),
		f("CVE-3", "lodash", finding.FixSoon),
	}}
	unfixed := Finding{ID: "CVE-4", Package: "openssl", Version: "3.1.4", Image: "app:1", Priority: finding.Backlog, Severity: "LOW"}
	c := Diff(prev, []Finding{exploited, raised, unfixed}, finding.FixSoon)
	c.Host, c.Target = "web-1", "/srv/app"
	c.Time = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return c
}

// capture starts a server that records the one request it expects.
func capture(t *testing.T, status int) (url string, body *[]byte, header *http.Header) {
	t.Helper()
	body, header = new([]byte), new(http.Header)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		*body, _ = io.ReadAll(r.Body)
		*header = r.Header
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/hooks/s3cret-token", body, header
}

func TestSendWebhookShape(t *testing.T) {
	url, body, header := capture(t, http.StatusNoContent)
	if err := SendWebhook(context.Background(), url, sample()); err != nil {
		t.Fatal(err)
	}
	if got := header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	const want = `{
  "version": 1,
  "host": "web-1",
  "target": "/srv/app",
  "time": "2026-01-02T03:04:05Z",
  "first_run": false,
  "new": [
    {
      "id": "CVE-2023-44487",
      "package": "golang.org/x/net",
      "version": "0.1.0",
      "fixed_in": "0.17.0",
      "priority": "fix_now",
      "severity": "MEDIUM",
      "kev": true,
      "epss": 0.9321
    }
  ],
  "raised": [
    {
      "id": "CVE-2",
      "package": "django",
      "version": "1.0.0",
      "fixed_in": "1.0.1",
      "priority": "fix_soon",
      "severity": "HIGH",
      "kev": false,
      "epss": null,
      "previous_priority": "plan"
    }
  ],
  "resolved": [
    {
      "id": "CVE-3",
      "package": "lodash",
      "version": "1.0.0",
      "fixed_in": "1.0.1",
      "priority": "fix_soon",
      "severity": "HIGH",
      "kev": false,
      "epss": null
    }
  ],
  "summary": {
    "fix_now": 1,
    "fix_soon": 1,
    "plan": 0,
    "backlog": 1
  }
}`
	var got, wanted any
	if err := json.Unmarshal(*body, &got); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, *body)
	}
	if err := json.Unmarshal([]byte(want), &wanted); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, wanted) {
		t.Errorf("payload = %s\nwant %s", *body, want)
	}
}

func TestWebhookEmptyListsAreArrays(t *testing.T) {
	url, body, _ := capture(t, http.StatusOK)
	c := Diff(nil, []Finding{f("CVE-1", "a", finding.FixNow)}, finding.FixSoon)
	if err := SendWebhook(context.Background(), url, c); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"first_run":true`, `"raised":[]`, `"resolved":[]`} {
		if !strings.Contains(string(*body), want) {
			t.Errorf("payload %s does not contain %s", *body, want)
		}
	}
}

func TestSendSlackText(t *testing.T) {
	url, body, _ := capture(t, http.StatusOK)
	if err := SendSlack(context.Background(), url, sample()); err != nil {
		t.Fatal(err)
	}
	var msg map[string]string
	if err := json.Unmarshal(*body, &msg); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, *body)
	}
	const want = `HardenKit Watch: /srv/app on web-1
1 new, 1 raised at or above FIX SOON.

New:
- FIX NOW: CVE-2023-44487 in golang.org/x/net 0.1.0, fixed in 0.17.0 (MEDIUM, exploited in the wild, EPSS 93.2%)

Raised:
- FIX SOON: CVE-2 in django 1.0.0, fixed in 1.0.1 (HIGH), was PLAN

Resolved:
- CVE-3 in lodash 1.0.0

Now: 1 FIX NOW, 1 FIX SOON, 0 PLAN, 1 BACKLOG.
`
	if len(msg) != 1 || msg["text"] != want {
		t.Errorf("text = %q\nwant  %q", msg["text"], want)
	}
}

func TestTextFirstRunAndLimit(t *testing.T) {
	var cur []Finding
	for i := 0; i < textLines+5; i++ {
		x := f("CVE-<"+string(rune('a'+i))+">", "pkg", finding.FixSoon)
		x.FixedIn, x.Image = "", "app:1"
		cur = append(cur, x)
	}
	c := Diff(nil, cur, finding.FixSoon)
	text := c.Text()
	for _, want := range []string{
		"First run: 15 findings at or above FIX SOON.",
		"- FIX SOON: CVE-<a> in pkg 1.0.0 (image app:1), no fix yet (HIGH)",
		"- and 5 more",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text does not contain %q:\n%s", want, text)
		}
	}
	if n := strings.Count(text, "\n- "); n != textLines+1 {
		t.Errorf("%d list lines, want %d", n, textLines+1)
	}

	// Slack reads <, > and & as markup.
	url, body, _ := capture(t, http.StatusOK)
	if err := SendSlack(context.Background(), url, c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(*body), `CVE-\u0026lt;a\u0026gt;`) {
		t.Errorf("Slack text is not escaped: %s", *body)
	}
}

func TestSendErrorsHideTheURL(t *testing.T) {
	url, _, _ := capture(t, http.StatusNotFound)
	err := SendWebhook(context.Background(), url, sample())
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("err = %v, want HTTP 404", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error shows the webhook path: %v", err)
	}

	// Nothing listens here, so the request itself fails.
	err = SendSlack(context.Background(), "http://127.0.0.1:1/hooks/s3cret-token?key=s3cret", sample())
	if err == nil {
		t.Fatal("no error from a closed port")
	}
	if strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error = %v, want the host and nothing else of the URL", err)
	}

	err = SendWebhook(context.Background(), "s3cret-not-a-url", sample())
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error = %v, want one that hides the value", err)
	}
}

func TestParsePriority(t *testing.T) {
	for in, want := range map[string]finding.Priority{
		"fix_now": finding.FixNow, "fix_soon": finding.FixSoon, "plan": finding.Plan, "BACKLOG": finding.Backlog,
	} {
		if got, err := ParsePriority(in); err != nil || got != want {
			t.Errorf("ParsePriority(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParsePriority("high"); err == nil {
		t.Error("ParsePriority accepted \"high\"")
	}
}
