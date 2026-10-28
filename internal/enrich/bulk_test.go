package enrich

import (
	"strings"
	"testing"
)

func TestParseEPSSCSV(t *testing.T) {
	in := "#model_version:v2026.06.15,score_date:2026-10-27T12:03:15Z\n" +
		"cve,epss,percentile\n" +
		"CVE-1999-0001,0.04753,0.91834\n" +
		"CVE-2021-44228,0.94358,0.99990\n"
	got, date, err := parseEPSSCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if date != "2026-10-27T12:03:15Z" {
		t.Errorf("date = %q", date)
	}
	if len(got) != 2 || got["CVE-2021-44228"] != 0.94358 {
		t.Errorf("scores = %v", got)
	}
}

func TestParseEPSSCSVEmpty(t *testing.T) {
	if _, _, err := parseEPSSCSV(strings.NewReader("cve,epss,percentile\n")); err == nil {
		t.Error("expected an error for a file with no scores")
	}
}
