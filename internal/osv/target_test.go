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
