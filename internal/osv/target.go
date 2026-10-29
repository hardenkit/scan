package osv

import (
	"net/url"
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
