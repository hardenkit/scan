// Package finding turns raw matches into ranked, deduplicated findings.
package finding

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/inventory"
	"github.com/hardenkit/scan/internal/osv"
)

// Priority is how urgently a finding should be fixed. Lower is more urgent.
type Priority int

const (
	FixNow  Priority = iota // exploited in the wild (CISA KEV)
	FixSoon                 // critical, or likely to be exploited (EPSS ≥ 10%)
	Plan                    // high severity
	Backlog                 // everything else
)

func (p Priority) String() string {
	return [...]string{"FIX NOW", "FIX SOON", "PLAN", "BACKLOG"}[p]
}

func (p Priority) MarshalText() ([]byte, error) {
	return []byte(strings.ReplaceAll(strings.ToLower(p.String()), " ", "_")), nil
}

// Finding is one vulnerability affecting one package.
type Finding struct {
	Priority   Priority          `json:"priority"`
	ID         string            `json:"id"` // CVE when known, otherwise the advisory ID
	Advisories []string          `json:"advisories"`
	Summary    string            `json:"summary"`
	Package    inventory.Package `json:"package"`
	FixedIn    string            `json:"fixed_in,omitempty"`
	Severity   string            `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN
	CVSS       *enrich.CVSS      `json:"cvss,omitempty"`
	EPSS       *float64          `json:"epss,omitempty"`
	KEV        *enrich.KEVEntry  `json:"kev,omitempty"`
	References []string          `json:"references,omitempty"`
}

// Build joins packages with their OSV records and enrichment data, merging
// advisories that describe the same CVE for the same package.
func Build(
	pkgs []inventory.Package,
	matches map[string][]string,
	vulns map[string]*osv.Vuln,
	kev map[string]enrich.KEVEntry,
	epss map[string]float64,
	cvss map[string]enrich.CVSS,
) []Finding {
	var out []Finding
	for _, p := range pkgs {
		byKey := map[string]*Finding{}
		var order []string
		t := osv.TargetFor(p.PURL, p.Name, p.Version)
		cmp := comparator(t.Ecosystem)
		for _, id := range matches[t.Key] {
			v, ok := vulns[id]
			if !ok {
				continue
			}
			key := v.CVE()
			if key == "" {
				key = v.ID
			}
			f, exists := byKey[key]
			if !exists {
				f = &Finding{ID: key, Package: p, Severity: "UNKNOWN"}
				byKey[key] = f
				order = append(order, key)
			}
			f.Advisories = append(f.Advisories, v.ID)
			if f.Summary == "" {
				f.Summary = firstLine(v.Summary, v.Details)
			}
			if f.Severity == "UNKNOWN" && v.Severity() != "" {
				f.Severity = v.Severity()
			}
			if fix := pickFix(cmp, t.Version, v.FixedVersions(t.Name, t.Ecosystem)); fix != "" &&
				(f.FixedIn == "" || cmp(fix, f.FixedIn) > 0) {
				f.FixedIn = fix // the highest fix across advisories closes all of them
			}
			for _, r := range v.References {
				if r.Type == "ADVISORY" || r.Type == "FIX" {
					f.References = appendUnique(f.References, r.URL)
				}
			}
		}
		for _, key := range order {
			f := byKey[key]
			if c, ok := cvss[f.ID]; ok {
				f.CVSS = &c
				if f.Severity == "UNKNOWN" && c.Severity != "" {
					f.Severity = c.Severity
				}
			}
			if e, ok := epss[f.ID]; ok {
				f.EPSS = &e
			}
			if k, ok := kev[f.ID]; ok {
				f.KEV = &k
			}
			f.Priority = prioritize(f)
			out = append(out, *f)
		}
	}
	Sort(out)
	return out
}

func prioritize(f *Finding) Priority {
	switch {
	case f.KEV != nil:
		return FixNow
	case f.Severity == "CRITICAL", f.EPSS != nil && *f.EPSS >= 0.10:
		return FixSoon
	case f.Severity == "HIGH":
		return Plan
	default:
		return Backlog
	}
}

// Sort orders findings by priority, then exploit likelihood, then CVSS score.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if ea, eb := deref(a.EPSS), deref(b.EPSS); ea != eb {
			return ea > eb
		}
		if sa, sb := severityRank(a.Severity), severityRank(b.Severity); sa != sb {
			return sa > sb
		}
		if ca, cb := score(a.CVSS), score(b.CVSS); ca != cb {
			return ca > cb
		}
		return a.Package.Name+a.ID < b.Package.Name+b.ID
	})
}

// Upgrade is the single version bump that resolves every fixable finding in a package.
type Upgrade struct {
	Priority  Priority          `json:"priority"` // most urgent finding it resolves
	Package   inventory.Package `json:"package"`
	UpgradeTo string            `json:"upgrade_to,omitempty"`
	Fixes     int               `json:"fixes"`   // findings resolved by the upgrade
	Unfixed   int               `json:"unfixed"` // findings with no fixed version yet
}

// UpgradePlan collapses sorted findings into one upgrade per package, most urgent first.
func UpgradePlan(fs []Finding) []Upgrade {
	var out []Upgrade
	idx := map[string]int{}
	for _, f := range fs {
		// Each image needs its own rebuild, so the same package in two images is two upgrades.
		key := f.Package.Image + "|" + f.Package.PURL + "|" + f.Package.Name + "@" + f.Package.Version
		i, ok := idx[key]
		if !ok {
			i = len(out)
			idx[key] = i
			out = append(out, Upgrade{Priority: f.Priority, Package: f.Package})
		}
		u := &out[i]
		if f.FixedIn == "" {
			u.Unfixed++
			continue
		}
		u.Fixes++
		cmp := comparator(osv.TargetFor(f.Package.PURL, f.Package.Name, f.Package.Version).Ecosystem)
		if u.UpgradeTo == "" || cmp(f.FixedIn, u.UpgradeTo) > 0 {
			u.UpgradeTo = f.FixedIn
		}
	}
	return out // fs is sorted by priority, so first-seen order is urgency order
}

// PickFix returns the lowest fixed version above current, or "" if none is.
// When the current version can't be compared, it falls back to the lowest fix.
func PickFix(current string, fixes []string) string {
	return pickFix(CompareVersions, current, fixes)
}

func pickFix(cmp func(a, b string) int, current string, fixes []string) string {
	var best string
	for _, f := range fixes {
		if current != "" && cmp(f, current) <= 0 {
			continue
		}
		if best == "" || cmp(f, best) < 0 {
			best = f
		}
	}
	return best
}

// comparator returns the version ordering for an OSV ecosystem: dpkg's for
// Debian and Ubuntu packages, the generic one otherwise.
func comparator(ecosystem string) func(a, b string) int {
	if strings.HasPrefix(ecosystem, "Debian:") || strings.HasPrefix(ecosystem, "Ubuntu:") {
		return CompareDebian
	}
	return CompareVersions
}

// CompareDebian compares Debian package versions ([epoch:]upstream[-revision])
// the way dpkg does: "~" sorts before everything, even the end of the string.
func CompareDebian(a, b string) int {
	ea, ua, ra := splitDebian(a)
	eb, ub, rb := splitDebian(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDebian(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// verrevcmp is dpkg's comparison of one version part.
func verrevcmp(a, b string) int {
	order := func(s string, i int) int {
		if i >= len(s) {
			return 0
		}
		c := s[i]
		switch {
		case c == '~':
			return -1
		case c >= '0' && c <= '9':
			return 0
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			return int(c)
		}
		return int(c) + 256
	}
	isDigit := func(s string, i int) bool { return i < len(s) && s[i] >= '0' && s[i] <= '9' }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a, i)) || (j < len(b) && !isDigit(b, j)) {
			if oa, ob := order(a, i), order(b, j); oa != ob {
				return oa - ob
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for isDigit(a, i) && isDigit(b, j) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(a, i) {
			return 1
		}
		if isDigit(b, j) {
			return -1
		}
		if first != 0 {
			return first
		}
	}
	return 0
}

// CompareVersions compares two version strings segment by segment, treating
// numeric segments numerically. It handles semver, PEP 440 and Maven-style
// versions well enough to choose an upgrade target; it is not a full
// per-ecosystem implementation. Pre-release tags sort before the release.
func CompareVersions(a, b string) int {
	sa, sb := segments(a), segments(b)
	for i := 0; i < max(len(sa), len(sb)); i++ {
		switch {
		case i >= len(sa):
			return releaseOrder(sb[i])
		case i >= len(sb):
			return -releaseOrder(sa[i])
		}
		if c := compareSegment(sa[i], sb[i]); c != 0 {
			return c
		}
	}
	return 0
}

// releaseOrder is the result of comparing "1.0" with "1.0<seg>": a trailing
// number makes the other side newer, a trailing tag (rc, beta) makes it older.
func releaseOrder(seg string) int {
	if isNum(seg) {
		return -1
	}
	return 1
}

func segments(v string) []string {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if i := strings.IndexAny(v, "+"); i >= 0 {
		v = v[:i] // build metadata doesn't affect ordering
	}
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	prevDigit := false
	for i, r := range v {
		switch {
		case unicode.IsDigit(r):
			if i > 0 && !prevDigit {
				flush()
			}
			cur.WriteRune(r)
			prevDigit = true
		case unicode.IsLetter(r):
			if prevDigit {
				flush()
			}
			cur.WriteRune(unicode.ToLower(r))
			prevDigit = false
		default:
			flush()
			prevDigit = false
		}
	}
	flush()
	return out
}

func compareSegment(a, b string) int {
	an, bn := isNum(a), isNum(b)
	switch {
	case an && bn:
		x, _ := strconv.ParseUint(strings.TrimLeft(a, "0")+"0", 10, 64)
		y, _ := strconv.ParseUint(strings.TrimLeft(b, "0")+"0", 10, 64)
		return cmp(x, y)
	case an:
		return 1 // 1.0.1 > 1.0.rc
	case bn:
		return -1
	default:
		return strings.Compare(a, b)
	}
}

func isNum(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}

func cmp[T int | uint64 | float64](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// AtLeast reports whether severity s meets threshold t (e.g. "HIGH").
func AtLeast(s, t string) bool { return severityRank(s) >= severityRank(t) }

func deref(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

func score(c *enrich.CVSS) float64 {
	if c == nil {
		return 0
	}
	return c.Score
}

func firstLine(candidates ...string) string {
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if i := strings.IndexByte(c, '\n'); i >= 0 {
			c = c[:i]
		}
		return c
	}
	return ""
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
