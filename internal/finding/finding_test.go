package finding

import (
	"testing"

	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/inventory"
	"github.com/hardenkit/scan/internal/osv"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.10", "1.2.9", 1},
		{"2.17.1", "2.14.1", 1},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-beta.2", 1},
		{"1.0", "1.0.1", -1},
		{"4.17.21", "4.17.20", 1},
		{"2.0.0a1", "2.0.0", -1},     // PEP 440 pre-release
		{"1.0.0+build5", "1.0.0", 0}, // build metadata ignored
		{"0.9.10", "0.10.0", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPickFix(t *testing.T) {
	cases := []struct {
		current string
		fixes   []string
		want    string
	}{
		{"2.14.1", []string{"2.3.1", "2.12.2", "2.15.0"}, "2.15.0"},
		{"1.0.0", []string{"1.0.5", "1.0.2"}, "1.0.2"},
		{"3.0.0", []string{"2.9.0"}, ""}, // already past every fix
		{"", []string{"1.4", "1.2"}, "1.2"},
	}
	for _, c := range cases {
		if got := PickFix(c.current, c.fixes); got != c.want {
			t.Errorf("PickFix(%q, %v) = %q, want %q", c.current, c.fixes, got, c.want)
		}
	}
}

func TestBuildMergesAliasesAndRanks(t *testing.T) {
	log4j := inventory.Package{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
	lodash := inventory.Package{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20?foo=bar"}

	affected := func(name string, fixed ...string) []osv.Affected {
		var evs []osv.Event
		for _, f := range fixed {
			evs = append(evs, osv.Event{Fixed: f})
		}
		return []osv.Affected{{Package: osv.AffectedPackage{Name: name}, Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: evs}}}}
	}
	vulns := map[string]*osv.Vuln{
		"GHSA-jfh8": {ID: "GHSA-jfh8", Aliases: []string{"CVE-2021-44228"}, Summary: "Remote code injection in Log4j",
			DatabaseSpecific: osv.DatabaseSpecific{Severity: "CRITICAL"}, Affected: affected(log4j.Name, "2.15.0", "2.3.1")},
		"GHSA-7rjr": {ID: "GHSA-7rjr", Aliases: []string{"CVE-2021-45046"}, Summary: "Incomplete fix",
			DatabaseSpecific: osv.DatabaseSpecific{Severity: "CRITICAL"}, Affected: affected(log4j.Name, "2.16.0")},
		"OTHER-1": {ID: "OTHER-1", Aliases: []string{"CVE-2021-44228"}, Affected: affected(log4j.Name, "2.15.0")},
		"GHSA-35jh": {ID: "GHSA-35jh", Aliases: []string{"CVE-2021-23337"}, Summary: "Command injection in lodash",
			DatabaseSpecific: osv.DatabaseSpecific{Severity: "HIGH"}, Affected: affected("lodash", "4.17.21")},
	}
	matches := map[string][]string{
		osv.NormalizePURL(log4j.PURL):  {"GHSA-jfh8", "OTHER-1", "GHSA-7rjr"},
		osv.NormalizePURL(lodash.PURL): {"GHSA-35jh"},
	}
	kev := map[string]enrich.KEVEntry{"CVE-2021-44228": {DueDate: "2021-12-24"}}
	epss := map[string]float64{"CVE-2021-44228": 0.94, "CVE-2021-45046": 0.92, "CVE-2021-23337": 0.02}

	got := Build([]inventory.Package{lodash, log4j}, matches, vulns, kev, epss, nil)

	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3 (aliases merged): %+v", len(got), got)
	}
	want := []struct {
		id  string
		pri Priority
		fix string
		adv int
	}{
		{"CVE-2021-44228", FixNow, "2.15.0", 2},
		{"CVE-2021-45046", FixSoon, "2.16.0", 1},
		{"CVE-2021-23337", Plan, "4.17.21", 1},
	}
	for i, w := range want {
		f := got[i]
		if f.ID != w.id || f.Priority != w.pri || f.FixedIn != w.fix || len(f.Advisories) != w.adv {
			t.Errorf("finding %d = {%s %s fix=%s advisories=%d}, want {%s %s fix=%s advisories=%d}",
				i, f.ID, f.Priority, f.FixedIn, len(f.Advisories), w.id, w.pri, w.fix, w.adv)
		}
	}
}

func TestUpgradePlanPicksHighestFixPerPackage(t *testing.T) {
	django := inventory.Package{Name: "django", Version: "3.2.0", PURL: "pkg:pypi/django@3.2.0"}
	lodash := inventory.Package{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"}
	fs := []Finding{
		{Priority: FixSoon, Package: django, FixedIn: "3.2.14"},
		{Priority: FixSoon, Package: lodash, FixedIn: "4.17.21"},
		{Priority: Plan, Package: django, FixedIn: "4.2.26"},
		{Priority: Backlog, Package: django, FixedIn: "3.2.25"},
		{Priority: Backlog, Package: lodash},
	}
	got := UpgradePlan(fs)
	if len(got) != 2 {
		t.Fatalf("got %d upgrades, want 2", len(got))
	}
	if u := got[0]; u.Package.Name != "django" || u.UpgradeTo != "4.2.26" || u.Fixes != 3 || u.Priority != FixSoon {
		t.Errorf("django upgrade = %+v", u)
	}
	if u := got[1]; u.Package.Name != "lodash" || u.UpgradeTo != "4.17.21" || u.Fixes != 1 || u.Unfixed != 1 {
		t.Errorf("lodash upgrade = %+v", u)
	}
}
