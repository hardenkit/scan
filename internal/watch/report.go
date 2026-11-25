package watch

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/httpx"
)

// MaxReportFindings is the most findings one report may carry. A scan with
// more is cut to the most urgent ones.
const MaxReportFindings = 5000

// Report is one scan of one target, as sent to a HardenKit dashboard. It
// holds package names, versions and vulnerability IDs: never file contents
// or file paths inside the target.
type Report struct {
	Scanner   string          `json:"scanner"`
	Host      string          `json:"host"`
	Target    string          `json:"target"`
	ScannedAt time.Time       `json:"scannedAt"`
	Packages  int             `json:"packages"`
	Findings  []ReportFinding `json:"findings"`
}

type ReportFinding struct {
	ID         string           `json:"id"`
	Advisories []string         `json:"advisories,omitempty"`
	Summary    string           `json:"summary,omitempty"`
	Package    ReportPackage    `json:"package"`
	FixedIn    string           `json:"fixedIn,omitempty"`
	Priority   finding.Priority `json:"priority"`
	Severity   string           `json:"severity"`
	CVSS       *float64         `json:"cvss"`
	EPSS       *float64         `json:"epss"`
	KEV        bool             `json:"kev"`
}

type ReportPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type,omitempty"`
	Image   string `json:"image,omitempty"`
}

// NewReport builds the report for a scan. fs must be sorted most urgent
// first, as a scan returns them. A package found in several places gives the
// same finding more than once; it is sent once. truncated is how many
// findings were left out because the scan had more than MaxReportFindings.
func NewReport(scanner, host, target string, at time.Time, packages int, fs []finding.Finding) (r Report, truncated int) {
	r = Report{
		Scanner:   clip(scanner, 64),
		Host:      clip(host, 255),
		Target:    clip(target, 1024),
		ScannedAt: at.UTC(),
		Packages:  packages,
		Findings:  []ReportFinding{},
	}
	seen := map[string]bool{}
	for _, f := range fs {
		key := f.ID + "\x00" + f.Package.Name + "\x00" + f.Package.Version + "\x00" + f.Package.Image
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(r.Findings) == MaxReportFindings {
			truncated++
			continue
		}
		rf := ReportFinding{
			ID:      clip(f.ID, 64),
			Summary: clip(f.Summary, 500),
			Package: ReportPackage{
				Name:    clip(f.Package.Name, 255),
				Version: clip(f.Package.Version, 255),
				Type:    clip(f.Package.Type, 255),
				Image:   clip(f.Package.Image, 255),
			},
			FixedIn:  clip(f.FixedIn, 255),
			Priority: f.Priority,
			Severity: f.Severity,
			EPSS:     f.EPSS,
			KEV:      f.KEV != nil,
		}
		for _, a := range f.Advisories {
			if len(rf.Advisories) < 20 {
				rf.Advisories = append(rf.Advisories, clip(a, 64))
			}
		}
		if f.CVSS != nil {
			score := f.CVSS.Score
			rf.CVSS = &score
		}
		r.Findings = append(r.Findings, rf)
	}
	return r, truncated
}

// clip cuts s to at most max characters, the limits the dashboard accepts.
func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		return string(r[:max])
	}
	return s
}

// ReportURL is where a project's reports go on the dashboard at base, e.g.
// "https://api.hardenkit.com".
func ReportURL(base, project string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("must be an http or https URL")
	}
	return strings.TrimRight(base, "/") + "/api/v1/projects/" + url.PathEscape(project) + "/scans", nil
}

// SendReport posts the report to endpoint (from ReportURL) with the API key.
func SendReport(ctx context.Context, endpoint, token string, r Report) error {
	return httpx.PostJSONWith(ctx, endpoint, http.Header{"X-Api-Key": {token}}, r)
}
