package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"path/filepath"
	"testing"

	"github.com/hardenkit/scan/internal/enrich"
)

func TestRoundTripAndLookup(t *testing.T) {
	db := New()
	db.NVDSyncedTo = "2026-10-28T00:00:00Z"
	e := db.Entry("CVE-2021-44228")
	e.Score, e.Severity, e.CVSSVersion = 10, "CRITICAL", "3.1"
	e.EPSS = 0.94
	e.KEV = &enrich.KEVEntry{DateAdded: "2021-12-10", Ransomware: true}
	db.Entry("CVE-2000-0001") // empty: pruned
	db.Prune()

	path := filepath.Join(t.TempDir(), "db.json.gz")
	if err := db.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	got, warn, err := Load(context.Background(), path)
	if err != nil || warn != "" {
		t.Fatalf("Load: %v %q", err, warn)
	}
	if len(got.CVEs) != 1 || got.NVDSyncedTo != db.NVDSyncedTo || got.Generated == "" {
		t.Fatalf("round trip lost data: %+v", got)
	}

	kev, epss, cvss := got.Lookup([]string{"CVE-2021-44228", "CVE-1999-9999"})
	if !kev["CVE-2021-44228"].Ransomware || epss["CVE-2021-44228"] != 0.94 || cvss["CVE-2021-44228"].Score != 10 {
		t.Errorf("lookup = %v %v %v", kev, epss, cvss)
	}
	if _, ok := cvss["CVE-1999-9999"]; ok {
		t.Error("unknown CVE should have no data")
	}
}

func TestReadRejectsOtherSchema(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(`{"schema":99,"cves":{}}`))
	gz.Close()
	if _, err := Read(&buf); err == nil {
		t.Error("expected schema mismatch error")
	}
}
