package osv

import "testing"

func TestTargetFor(t *testing.T) {
	for _, c := range []struct {
		purl, name, version string
		want                Target
	}{
		{
			"pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?arch=arm64&distro=debian-13&upstream=openssl", "libssl3t64", "3.5.7-1~deb13u3",
			Target{Key: "Debian:13/openssl@3.5.7-1~deb13u3", Ecosystem: "Debian:13", Name: "openssl", Version: "3.5.7-1~deb13u3"},
		},
		{
			"pkg:deb/debian/libcap2@1%3A2.75-10%2Bdeb13u1%2Bb3?arch=arm64&distro=debian-13&upstream=libcap2%402.75-10%2Bdeb13u1", "libcap2", "1:2.75-10+deb13u1+b3",
			Target{Key: "Debian:13/libcap2@2.75-10+deb13u1", Ecosystem: "Debian:13", Name: "libcap2", Version: "2.75-10+deb13u1"},
		},
		{
			"pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.6?arch=amd64&distro=ubuntu-24.04", "curl", "8.5.0-2ubuntu10.6",
			Target{Key: "Ubuntu:24.04:LTS/curl@8.5.0-2ubuntu10.6", Ecosystem: "Ubuntu:24.04:LTS", Name: "curl", Version: "8.5.0-2ubuntu10.6"},
		},
		{
			"pkg:deb/ubuntu/curl@8.9.1-2ubuntu2?distro=ubuntu-24.10", "curl", "8.9.1-2ubuntu2",
			Target{Key: "Ubuntu:24.10/curl@8.9.1-2ubuntu2", Ecosystem: "Ubuntu:24.10", Name: "curl", Version: "8.9.1-2ubuntu2"},
		},
		{
			"pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=x86_64&upstream=openssl&distro=alpine-3.20.3", "libcrypto3", "3.3.2-r0",
			Target{Key: "Alpine:v3.20/openssl@3.3.2-r0", Ecosystem: "Alpine:v3.20", Name: "openssl", Version: "3.3.2-r0"},
		},
		{
			// No distro qualifier: fall back to purl matching.
			"pkg:deb/debian/curl@7.88.1-10", "curl", "7.88.1-10",
			Target{Key: "pkg:deb/debian/curl@7.88.1-10", PURL: "pkg:deb/debian/curl@7.88.1-10", Name: "curl", Version: "7.88.1-10"},
		},
		{
			"pkg:npm/%40babel/core@7.0.0", "@babel/core", "7.0.0",
			Target{Key: "pkg:npm/%40babel/core@7.0.0", PURL: "pkg:npm/%40babel/core@7.0.0", Name: "@babel/core", Version: "7.0.0"},
		},
		{
			"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", "log4j-core", "2.14.1",
			Target{Key: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
		},
	} {
		if got := TargetFor(c.purl, c.name, c.version); got != c.want {
			t.Errorf("TargetFor(%q)\n got %+v\nwant %+v", c.purl, got, c.want)
		}
	}
}

func TestFixedVersionsByEcosystem(t *testing.T) {
	v := &Vuln{Affected: []Affected{
		{Package: AffectedPackage{Ecosystem: "Debian:12", Name: "openssl"}, Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "3.0.15-1~deb12u1"}}}}},
		{Package: AffectedPackage{Ecosystem: "Debian:13", Name: "openssl"}, Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "3.5.8-1~deb13u1"}}}}},
	}}
	if got := v.FixedVersions("openssl", "Debian:13"); len(got) != 1 || got[0] != "3.5.8-1~deb13u1" {
		t.Errorf("Debian:13 fixes = %v", got)
	}
	if got := v.FixedVersions("openssl", ""); len(got) != 2 {
		t.Errorf("all fixes = %v", got)
	}
}

func TestActionTarget(t *testing.T) {
	for _, c := range []struct{ purl, key, version string }{
		{"pkg:github/tj-actions/changed-files@v45", "GitHub Actions/tj-actions/changed-files@45", "45"},
		{"pkg:github/actions/cache@v6.1.0", "GitHub Actions/actions/cache@6.1.0", "6.1.0"},
		{"pkg:github/acme/deploy@main", "GitHub Actions/acme/deploy", ""},
		{"pkg:github/%24/.github#actions/setup", "GitHub Actions/$/.github", ""},
	} {
		got := TargetFor(c.purl, "", "")
		if got.Key != c.key || got.Version != c.version || got.Ecosystem != ActionsEcosystem {
			t.Errorf("TargetFor(%q) = %+v, want key %q version %q", c.purl, got, c.key, c.version)
		}
	}
}

func TestActionAffected(t *testing.T) {
	fixed := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "46.0.1"}}}}
	// CVE-2025-24362 in github/codeql-action: fixed in v3, v2 retired unfixed.
	codeql := []Range{
		{Type: "ECOSYSTEM", Events: []Event{{Introduced: "3.26.11"}, {Fixed: "3.28.3"}}},
		{Type: "ECOSYSTEM", Events: []Event{{Introduced: "2.26.11"}}},
	}
	window := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "2.1.0"}, {LastAffected: "2.3.4"}}}}
	for _, c := range []struct {
		version string
		ranges  []Range
		want    bool
	}{
		{"45", fixed, true},      // v45 moves within 45.x, all before the fix
		{"46", fixed, false},     // v46 points at 46.0.1 or later
		{"46.0.0", fixed, true},  // an exact release before the fix
		{"46.0.1", fixed, false}, // the fix
		{"4.39.1", codeql, false},
		{"3.28.3", codeql, false},
		{"3.27.0", codeql, true},
		{"3", codeql, false}, // v3 now points past the fix
		{"2.26.11", codeql, true},
		{"2", codeql, true},
		{"2.0.9", window, false},
		{"2.2", window, true}, // the newest 2.2.x is inside the window
		{"2.3.4", window, true},
		{"2.3.5", window, false},
	} {
		if got := actionAffected(c.version, c.ranges); got != c.want {
			t.Errorf("actionAffected(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}
