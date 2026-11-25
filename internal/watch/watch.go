// Package watch compares a scan with the previous one for the same target
// and tells the owner what newly needs attention.
package watch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/httpx"
)

// PayloadVersion is the version of the webhook JSON shape.
const PayloadVersion = 1

// Finding is one vulnerability in one package, as kept in the state file
// and sent in alerts.
type Finding struct {
	ID       string           `json:"id"`
	Package  string           `json:"package"`
	Version  string           `json:"version"`
	Image    string           `json:"image,omitempty"`
	FixedIn  string           `json:"fixed_in"`
	Priority finding.Priority `json:"priority"`
	Severity string           `json:"severity"`
	KEV      bool             `json:"kev"`
	EPSS     *float64         `json:"epss"`
	// PreviousPriority is set on raised findings only.
	PreviousPriority *finding.Priority `json:"previous_priority,omitempty"`
}

// key is what makes two findings the same one across runs.
func (f Finding) key() string {
	return f.ID + "\x00" + f.Package + "\x00" + f.Version + "\x00" + f.Image
}

// FromScan converts scan findings, keeping their order. A package found in
// several places gives the same finding more than once; it is kept once.
func FromScan(fs []finding.Finding) []Finding {
	out := make([]Finding, 0, len(fs))
	seen := map[string]int{}
	for _, f := range fs {
		w := Finding{
			ID:       f.ID,
			Package:  f.Package.Name,
			Version:  f.Package.Version,
			Image:    f.Package.Image,
			FixedIn:  f.FixedIn,
			Priority: f.Priority,
			Severity: f.Severity,
			KEV:      f.KEV != nil,
			EPSS:     f.EPSS,
		}
		if i, ok := seen[w.key()]; ok {
			if w.Priority < out[i].Priority {
				out[i] = w
			}
			continue
		}
		seen[w.key()] = len(out)
		out = append(out, w)
	}
	return out
}

// Summary counts a target's current findings by priority.
type Summary struct {
	FixNow  int `json:"fix_now"`
	FixSoon int `json:"fix_soon"`
	Plan    int `json:"plan"`
	Backlog int `json:"backlog"`
}

func (s Summary) String() string {
	return fmt.Sprintf("%d FIX NOW, %d FIX SOON, %d PLAN, %d BACKLOG", s.FixNow, s.FixSoon, s.Plan, s.Backlog)
}

// Change is what one pass found for one target. Its JSON form is the
// webhook payload.
type Change struct {
	Version  int       `json:"version"`
	Host     string    `json:"host"`
	Target   string    `json:"target"`
	Time     time.Time `json:"time"`
	FirstRun bool      `json:"first_run"`
	New      []Finding `json:"new"`
	Raised   []Finding `json:"raised"`
	Resolved []Finding `json:"resolved"`
	Summary  Summary   `json:"summary"`

	// AlertOn is the least urgent priority that alerts.
	AlertOn finding.Priority `json:"-"`
}

// Diff compares the current findings with the saved ones. prev is nil on the
// first run for a target; then everything at or above alertOn is new.
//
//   - new: at or above alertOn and not there before.
//   - raised: there before at a less urgent priority, now at or above alertOn.
//   - resolved: was at or above alertOn and is gone.
func Diff(prev *Target, cur []Finding, alertOn finding.Priority) Change {
	c := Change{
		Version:  PayloadVersion,
		FirstRun: prev == nil,
		New:      []Finding{},
		Raised:   []Finding{},
		Resolved: []Finding{},
		AlertOn:  alertOn,
	}
	before := map[string]Finding{}
	if prev != nil {
		for _, f := range prev.Findings {
			before[f.key()] = f
		}
	}
	now := map[string]bool{}
	for _, f := range cur {
		now[f.key()] = true
		switch f.Priority {
		case finding.FixNow:
			c.Summary.FixNow++
		case finding.FixSoon:
			c.Summary.FixSoon++
		case finding.Plan:
			c.Summary.Plan++
		default:
			c.Summary.Backlog++
		}
		if f.Priority > alertOn {
			continue
		}
		old, existed := before[f.key()]
		switch {
		case !existed:
			c.New = append(c.New, f)
		case old.Priority > f.Priority:
			was := old.Priority
			f.PreviousPriority = &was
			c.Raised = append(c.Raised, f)
		}
	}
	if prev != nil {
		for _, f := range prev.Findings {
			if !now[f.key()] && f.Priority <= alertOn {
				c.Resolved = append(c.Resolved, f)
			}
		}
	}
	for _, list := range [][]Finding{c.New, c.Raised, c.Resolved} {
		sort.SliceStable(list, func(i, j int) bool { return list[i].Priority < list[j].Priority })
	}
	return c
}

// Alert reports whether the change should be sent: only new and raised
// findings do that, resolved ones never on their own.
func (c Change) Alert() bool { return len(c.New) > 0 || len(c.Raised) > 0 }

// textLines caps the findings listed in a message; chat services cut long
// messages off (Discord at 2000 characters).
const textLines = 10

// Text is the readable form of the change, for stdout and chat messages.
func (c Change) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HardenKit Watch: %s on %s\n", c.Target, c.Host)
	level := c.AlertOn.String()
	if c.FirstRun {
		fmt.Fprintf(&b, "First run: %s at or above %s.\n", count(len(c.New), "finding"), level)
	} else {
		fmt.Fprintf(&b, "%d new, %d raised at or above %s.\n", len(c.New), len(c.Raised), level)
	}

	left := textLines
	section := func(title string, list []Finding, line func(Finding) string) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for i, f := range list {
			if left == 0 {
				fmt.Fprintf(&b, "- and %d more\n", len(list)-i)
				return
			}
			left--
			fmt.Fprintf(&b, "- %s\n", line(f))
		}
	}
	section("New", c.New, describe)
	section("Raised", c.Raised, func(f Finding) string {
		s := describe(f)
		if f.PreviousPriority != nil {
			s += ", was " + f.PreviousPriority.String()
		}
		return s
	})
	section("Resolved", c.Resolved, func(f Finding) string {
		return f.ID + " in " + pkg(f)
	})

	fmt.Fprintf(&b, "\nNow: %s.\n", c.Summary)
	return b.String()
}

// describe is one finding on one line, e.g.
// "FIX NOW: CVE-2023-44487 in golang.org/x/net 0.1.0, fixed in 0.17.0 (MEDIUM, exploited in the wild, EPSS 100.0%)".
func describe(f Finding) string {
	s := fmt.Sprintf("%s: %s in %s", f.Priority, f.ID, pkg(f))
	if f.FixedIn != "" {
		s += ", fixed in " + f.FixedIn
	} else {
		s += ", no fix yet"
	}
	notes := []string{f.Severity}
	if f.KEV {
		notes = append(notes, "exploited in the wild")
	}
	if f.EPSS != nil {
		notes = append(notes, fmt.Sprintf("EPSS %.1f%%", *f.EPSS*100))
	}
	return s + " (" + strings.Join(notes, ", ") + ")"
}

func pkg(f Finding) string {
	s := f.Package + " " + f.Version
	if f.Image != "" {
		s += " (image " + f.Image + ")"
	}
	return s
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// SendWebhook posts the change as JSON to url.
func SendWebhook(ctx context.Context, url string, c Change) error {
	return httpx.PostJSON(ctx, url, c)
}

// slackEscape covers the three characters Slack treats as markup.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// SendSlack posts the change as a Slack incoming-webhook message. Discord's
// "/slack" webhook endpoint and Mattermost take the same body.
func SendSlack(ctx context.Context, url string, c Change) error {
	return httpx.PostJSON(ctx, url, map[string]string{"text": slackEscape.Replace(c.Text())})
}

// ParsePriority reads an --alert-on value.
func ParsePriority(s string) (finding.Priority, error) {
	var p finding.Priority
	if err := p.UnmarshalText([]byte(strings.ToLower(s))); err != nil {
		return 0, fmt.Errorf("must be fix_now, fix_soon, plan or backlog, got %q", s)
	}
	return p, nil
}
