// Package enrich adds exploitation and severity context to CVEs:
// CISA KEV (exploited in the wild), FIRST EPSS (exploit likelihood) and NVD (CVSS).
package enrich

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hardenkit/scan/internal/httpx"
)

const (
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL = "https://api.first.org/data/v1/epss"
	nvdURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

// KEVEntry is a CVE listed in CISA's Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Ransomware bool   `json:"ransomware"`
}

// KEV returns the CISA KEV catalog keyed by CVE ID.
func KEV(ctx context.Context) (map[string]KEVEntry, error) {
	var feed struct {
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			DateAdded  string `json:"dateAdded"`
			DueDate    string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := httpx.GetJSON(ctx, kevURL, nil, &feed); err != nil {
		return nil, fmt.Errorf("CISA KEV: %w", err)
	}
	out := make(map[string]KEVEntry, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		out[v.CVE] = KEVEntry{
			DateAdded:  v.DateAdded,
			DueDate:    v.DueDate,
			Ransomware: strings.EqualFold(v.Ransomware, "Known"),
		}
	}
	return out, nil
}

// EPSS returns the probability (0–1) that each CVE is exploited in the next 30 days.
func EPSS(ctx context.Context, cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	const chunk = 100
	for start := 0; start < len(cves); start += chunk {
		end := min(start+chunk, len(cves))
		q := url.Values{}
		q.Set("cve", strings.Join(cves[start:end], ","))
		q.Set("limit", strconv.Itoa(chunk))
		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := httpx.GetJSON(ctx, epssURL+"?"+q.Encode(), nil, &resp); err != nil {
			return out, fmt.Errorf("EPSS: %w", err)
		}
		for _, d := range resp.Data {
			if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				out[d.CVE] = f
			}
		}
	}
	return out, nil
}

// CVSS is a CVE's base score from NVD.
type CVSS struct {
	Version  string  `json:"version"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector"`
}

// NVD fetches CVSS scores for cves. apiKey may be empty, in which case NVD's
// public rate limit (5 requests / 30s) applies and requests are paced to match.
func NVD(ctx context.Context, cves []string, apiKey string) (map[string]CVSS, error) {
	pace := 6 * time.Second
	header := http.Header{}
	if apiKey != "" {
		pace = 700 * time.Millisecond // 50 requests / 30s with a key
		header.Set("apiKey", apiKey)
	}

	out := map[string]CVSS{}
	for i, id := range cves {
		if i > 0 {
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			case <-time.After(pace):
			}
		}
		var resp struct {
			Vulnerabilities []struct {
				CVE struct {
					Metrics struct {
						V40 []nvdMetric `json:"cvssMetricV40"`
						V31 []nvdMetric `json:"cvssMetricV31"`
						V30 []nvdMetric `json:"cvssMetricV30"`
						V2  []nvdMetric `json:"cvssMetricV2"`
					} `json:"metrics"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if err := httpx.GetJSON(ctx, nvdURL+"?cveId="+url.QueryEscape(id), header, &resp); err != nil {
			return out, fmt.Errorf("NVD: %w", err)
		}
		if len(resp.Vulnerabilities) == 0 {
			continue
		}
		m := resp.Vulnerabilities[0].CVE.Metrics
		for _, set := range [][]nvdMetric{m.V40, m.V31, m.V30, m.V2} {
			if best, ok := pickMetric(set); ok {
				sev := best.CVSSData.BaseSeverity
				if sev == "" {
					sev = best.BaseSeverity
				}
				out[id] = CVSS{
					Version:  best.CVSSData.Version,
					Score:    best.CVSSData.BaseScore,
					Severity: strings.ToUpper(sev),
					Vector:   best.CVSSData.VectorString,
				}
				break
			}
		}
	}
	return out, nil
}

type nvdMetric struct {
	CVSSData struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 keeps it outside cvssData
	Type         string `json:"type"`
}

// pickMetric prefers NVD's own ("Primary") score over a CNA's ("Secondary").
func pickMetric(set []nvdMetric) (nvdMetric, bool) {
	if len(set) == 0 {
		return nvdMetric{}, false
	}
	for _, m := range set {
		if m.Type == "Primary" {
			return m, true
		}
	}
	return set[0], true
}
