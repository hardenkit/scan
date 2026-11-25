package watch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/inventory"
)

func TestNewReport(t *testing.T) {
	epss := 0.997
	fs := []finding.Finding{
		{
			Priority: finding.FixNow, ID: "CVE-2025-55182", Advisories: []string{"GHSA-9qr9-h5gf-34mp"},
			Summary: strings.Repeat("é", 600),
			Package: inventory.Package{Name: "next", Version: "15.1.0", Type: "npm", Locations: []string{"/srv/app/package-lock.json"}},
			FixedIn: "15.1.9", Severity: "CRITICAL", CVSS: &enrich.CVSS{Score: 10}, EPSS: &epss, KEV: &enrich.KEVEntry{},
		},
		// The same finding from a second lockfile.
		{Priority: finding.FixNow, ID: "CVE-2025-55182", Package: inventory.Package{Name: "next", Version: "15.1.0"}, Severity: "CRITICAL"},
		{Priority: finding.Backlog, ID: "GHSA-aaaa-bbbb-cccc", Package: inventory.Package{Name: "left-pad", Version: "1.0.0"}, Severity: "UNKNOWN"},
	}
	at := time.Date(2026, 11, 25, 3, 0, 0, 0, time.UTC)
	r, truncated := NewReport("0.2.0", "web-1", "/srv/app", at, 412, fs)
	if truncated != 0 || len(r.Findings) != 2 {
		t.Fatalf("got %d findings, %d truncated; want 2 and 0", len(r.Findings), truncated)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["scanner"] != "0.2.0" || got["host"] != "web-1" || got["target"] != "/srv/app" ||
		got["scannedAt"] != "2026-11-25T03:00:00Z" || got["packages"] != float64(412) {
		t.Errorf("header fields wrong: %s", data)
	}
	first := got["findings"].([]any)[0].(map[string]any)
	if first["priority"] != "fix_now" || first["kev"] != true || first["cvss"] != float64(10) ||
		first["epss"] != 0.997 || first["fixedIn"] != "15.1.9" {
		t.Errorf("first finding wrong: %v", first)
	}
	if n := len([]rune(first["summary"].(string))); n != 500 {
		t.Errorf("summary has %d characters, want 500", n)
	}
	second := got["findings"].([]any)[1].(map[string]any)
	if second["cvss"] != nil || second["epss"] != nil || second["kev"] != false {
		t.Errorf("second finding wrong: %v", second)
	}
	// File locations inside the target never leave the machine.
	if strings.Contains(string(data), "package-lock.json") {
		t.Errorf("report contains a file location: %s", data)
	}
}

func TestNewReportTruncates(t *testing.T) {
	fs := make([]finding.Finding, MaxReportFindings+3)
	for i := range fs {
		fs[i] = finding.Finding{ID: "CVE-1", Package: inventory.Package{Name: "p", Version: time.Duration(i).String()}, Severity: "LOW", Priority: finding.Backlog}
	}
	r, truncated := NewReport("dev", "h", "t", time.Now(), 1, fs)
	if len(r.Findings) != MaxReportFindings || truncated != 3 {
		t.Errorf("got %d findings, %d truncated", len(r.Findings), truncated)
	}
}

func TestReportURL(t *testing.T) {
	got, err := ReportURL("https://api.hardenkit.com/", "01ABC")
	if err != nil || got != "https://api.hardenkit.com/api/v1/projects/01ABC/scans" {
		t.Errorf("ReportURL = %q, %v", got, err)
	}
	if _, err := ReportURL("api.hardenkit.com", "01ABC"); err == nil {
		t.Error("a URL without a scheme was accepted")
	}
}

func TestSendReport(t *testing.T) {
	var key, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-API-Key")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		if key != "mk_good" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":{"code":"INVALID_API_KEY","message":"mk_bad is not a key"}}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	endpoint, _ := ReportURL(srv.URL, "p1")
	r, _ := NewReport("dev", "h", "/t", time.Now(), 0, nil)

	if err := SendReport(context.Background(), endpoint, "mk_good", r); err != nil {
		t.Fatalf("SendReport: %v", err)
	}
	if !strings.Contains(body, `"findings":[]`) {
		t.Errorf("an empty scan must send an empty list, got %s", body)
	}
	err := SendReport(context.Background(), endpoint, "mk_bad", r)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("want an HTTP 401 error, got %v", err)
	}
	if strings.Contains(err.Error(), "mk_bad") || strings.Contains(err.Error(), "/api/v1") {
		t.Errorf("the error repeats the key or the path: %v", err)
	}
}
