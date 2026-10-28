package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/inventory"
)

func TestMarkdown(t *testing.T) {
	pkg := inventory.Package{Name: "weird|name", Version: "1.0.0", PURL: "pkg:npm/weird@1.0.0"}
	var fs []finding.Finding
	for i := 0; i < markdownRowLimit+3; i++ {
		fs = append(fs, finding.Finding{ID: "CVE-2021-44228", Package: pkg, FixedIn: "1.0.1", Severity: "HIGH"})
	}
	fs[0].KEV = &enrich.KEVEntry{}
	r := Result{Target: ".", Packages: 1, Findings: fs, Upgrades: finding.UpgradePlan(fs), Sources: []string{"OSV.dev"}}

	var buf bytes.Buffer
	if err := Markdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"1 exploited in the wild",
		"### Upgrade plan",
		"`weird\\|name`",    // pipe escaped inside the table
		"| `1.0.1` | 103 |", // one upgrade fixes everything
		"3 more not shown",  // row limit applied
		"**(exploited)**",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestMarkdownClean(t *testing.T) {
	var buf bytes.Buffer
	Markdown(&buf, Result{Target: ".", Packages: 4})
	if !strings.Contains(buf.String(), "No known vulnerabilities found.") {
		t.Error(buf.String())
	}
}
