package osv

import (
	"net/url"
	"regexp"
	"strings"
)

// Target is how one package is matched against OSV. Language packages are
// matched by purl. Linux distribution packages are matched by release
// ecosystem ("Debian:13", "Alpine:v3.20"), source package name and version,
// because distributions file advisories per release and per source package
// (libssl3 is fixed in "openssl"), and backport fixes without changing the
// upstream version.
type Target struct {
	Key       string // groups packages that match identically
	PURL      string // purl matching
	Ecosystem string // ecosystem matching
	Name      string // the name advisories use for this package
	Version   string
}

// TargetFor returns the target for a package with the given purl, name and
// version (as the cataloger reported them).
func TargetFor(purl, name, version string) Target {
	if t, ok := distroTarget(purl, version); ok {
		return t
	}
	if t, ok := actionTarget(purl); ok {
		return t
	}
	// OSV names Maven packages "group:artifact"; catalogers report the artifact.
	if p, ok := parsePURL(purl); ok && p.typ == "maven" && p.namespace != "" {
		name = p.namespace + ":" + p.name
	}
	n := NormalizePURL(purl)
	return Target{Key: n, PURL: n, Name: name, Version: version}
}

type purlParts struct {
	typ, namespace, name, version string
	qualifiers                    url.Values
}

func parsePURL(s string) (purlParts, bool) {
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return purlParts{}, false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, qs, _ := strings.Cut(rest, "?")
	var p purlParts
	p.qualifiers, _ = url.ParseQuery(qs)
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		p.version, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return purlParts{}, false
	}
	p.typ = strings.ToLower(parts[0])
	p.name, _ = url.PathUnescape(parts[len(parts)-1])
	if len(parts) > 2 {
		ns := make([]string, 0, len(parts)-2)
		for _, seg := range parts[1 : len(parts)-1] {
			seg, _ = url.PathUnescape(seg)
			ns = append(ns, seg)
		}
		p.namespace = strings.Join(ns, "/")
	}
	return p, true
}

func distroTarget(purl, version string) (Target, bool) {
	p, ok := parsePURL(purl)
	if !ok || (p.typ != "deb" && p.typ != "apk") {
		return Target{}, false
	}
	distro := p.qualifiers.Get("distro") // e.g. "debian-13", "ubuntu-24.04", "alpine-3.20.3"
	_, release, _ := strings.Cut(distro, "-")

	var eco string
	switch strings.ToLower(p.namespace) {
	case "debian":
		if major, _, _ := strings.Cut(release, "."); major != "" {
			eco = "Debian:" + major
		}
	case "ubuntu":
		if release != "" {
			eco = "Ubuntu:" + release
			if isUbuntuLTS(release) {
				eco += ":LTS"
			}
		}
	case "alpine":
		if parts := strings.Split(release, "."); len(parts) >= 2 {
			eco = "Alpine:v" + parts[0] + "." + parts[1]
		}
	case "wolfi":
		eco = "Wolfi"
	case "chainguard":
		eco = "Chainguard"
	}
	if eco == "" {
		return Target{}, false
	}

	// Advisories name the source package: upstream=openssl or upstream=glibc@2.36-9.
	name, ver := p.name, version
	if up := p.qualifiers.Get("upstream"); up != "" {
		upName, upVer, hasVer := strings.Cut(up, "@")
		name = upName
		if hasVer && upVer != "" {
			ver = upVer
		}
	}
	if ver == "" {
		ver = p.version
	}
	return Target{Key: eco + "/" + name + "@" + ver, Ecosystem: eco, Name: name, Version: ver}, true
}

// isUbuntuLTS reports whether an Ubuntu release (e.g. "24.04") is an LTS:
// the April release of even years.
func isUbuntuLTS(release string) bool {
	year, month, ok := strings.Cut(release, ".")
	if !ok || month != "04" || len(year) != 2 {
		return false
	}
	return (year[1]-'0')%2 == 0
}

// ActionsEcosystem is OSV's ecosystem for GitHub Actions.
const ActionsEcosystem = "GitHub Actions"

// actionTarget matches a GitHub Action (pkg:github/owner/repo@v4.2.0) by
// owner/repo and its version tag. Actions referenced by branch, by an
// unannotated commit or from the same repository get no version and aren't
// matched.
func actionTarget(purl string) (Target, bool) {
	p, ok := parsePURL(purl)
	if !ok || p.typ != "github" {
		return Target{}, false
	}
	name := p.namespace + "/" + p.name
	t := Target{Key: ActionsEcosystem + "/" + name, Ecosystem: ActionsEcosystem, Name: name}
	if p.namespace == "$" {
		return t, true // a local action ($ is Syft's name for this repository)
	}
	if v := strings.TrimPrefix(p.version, "v"); actionVersion.MatchString(v) {
		t.Version = v
		t.Key += "@" + v
	}
	return t, true
}

var actionVersion = regexp.MustCompile(`^\d+(\.\d+){0,2}$`)

// actionAffected reports whether an action at version (a tag such as "45"
// or "4.2.0") is in one of the advisory's ranges. A tag without a patch
// number is a moving tag that points at the newest release of that line, so
// "v45" is compared as the newest 45.x.
//
// Advisories for actions list one range per major version, and a line that
// was retired without a fix has no end ("introduced 2.26.11"). Such a range
// only covers its own major version when the advisory has a range for a
// later one.
func actionAffected(version string, ranges []Range) bool {
	v := versionParts(version, true)
	maxMajor := -1
	for _, r := range ranges {
		for _, e := range r.Events {
			if e.Introduced != "" {
				maxMajor = max(maxMajor, versionParts(e.Introduced, false)[0])
			}
		}
	}
	for _, r := range ranges {
		if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
			continue
		}
		if major, open := openRange(r); open && major < maxMajor && v[0] != major {
			continue
		}
		// OSV's evaluation: walk the events in order, entering a range at
		// "introduced" and leaving it at "fixed" or after "last_affected".
		affected := false
		for _, e := range r.Events {
			switch {
			case e.Introduced != "":
				if e.Introduced == "0" || compareParts(v, versionParts(e.Introduced, false)) >= 0 {
					affected = true
				}
			case e.Fixed != "":
				if compareParts(v, versionParts(e.Fixed, false)) >= 0 {
					affected = false
				}
			case e.LastAffected != "":
				if compareParts(v, versionParts(e.LastAffected, false)) > 0 {
					affected = false
				}
			}
		}
		if affected {
			return true
		}
	}
	return false
}

// openRange reports whether a range has no fixed or last-affected version,
// and the major version it was introduced in.
func openRange(r Range) (major int, open bool) {
	open = true
	for _, e := range r.Events {
		switch {
		case e.Introduced != "":
			major = versionParts(e.Introduced, false)[0]
		case e.Fixed != "", e.LastAffected != "":
			open = false
		}
	}
	return major, open
}

// versionParts parses "4.2.0" into [4 2 0]. Missing parts are 0, or the
// largest value when open is set (a moving tag).
func versionParts(v string, open bool) [3]int {
	var out [3]int
	if open {
		out = [3]int{1 << 30, 1 << 30, 1 << 30}
	}
	v = strings.TrimPrefix(v, "v")
	for i, part := range strings.SplitN(v, ".", 3) {
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}

func compareParts(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
