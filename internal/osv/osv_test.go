package osv

import "testing"

func TestCVE(t *testing.T) {
	nvd := func(id string) Reference {
		return Reference{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/" + id}
	}
	cases := []struct {
		name string
		v    Vuln
		want string
	}{
		{"own id", Vuln{ID: "CVE-2021-44228"}, "CVE-2021-44228"},
		{"alias", Vuln{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}}, "CVE-2021-44228"},
		{"alias wins over reference", Vuln{ID: "GHSA-x", Aliases: []string{"CVE-2024-1"}, References: []Reference{nvd("CVE-2024-2")}}, "CVE-2024-1"},
		// Next.js's React2Shell advisory: no alias, one NVD advisory link.
		{"nvd reference", Vuln{ID: "GHSA-9qr9-h5gf-34mp", References: []Reference{
			{Type: "WEB", URL: "https://github.com/facebook/react/security/advisories/GHSA-fv66-9v8q-g76r"},
			nvd("CVE-2025-55182"),
		}}, "CVE-2025-55182"},
		{"two different nvd references", Vuln{ID: "GHSA-x", References: []Reference{nvd("CVE-2024-1"), nvd("CVE-2024-2")}}, ""},
		{"nvd link that is not an advisory reference", Vuln{ID: "GHSA-x", References: []Reference{
			{Type: "WEB", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1"},
		}}, ""},
		{"none", Vuln{ID: "GHSA-x"}, ""},
	}
	for _, c := range cases {
		if got := c.v.CVE(); got != c.want {
			t.Errorf("%s: CVE() = %q, want %q", c.name, got, c.want)
		}
	}
}
