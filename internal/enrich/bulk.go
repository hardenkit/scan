package enrich

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hardenkit/scan/internal/httpx"
)

const epssBulkURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// EPSSAll downloads the full daily EPSS file. It returns every CVE's score and
// the date the scores were computed.
func EPSSAll(ctx context.Context) (map[string]float64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssBulkURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", httpx.UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("EPSS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("EPSS: HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("EPSS: %w", err)
	}
	return parseEPSSCSV(gz)
}

// parseEPSSCSV reads the EPSS file: a "#model_version:...,score_date:..."
// comment line, a "cve,epss,percentile" header, then one row per CVE.
func parseEPSSCSV(r io.Reader) (map[string]float64, string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	out := map[string]float64{}
	var date string
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("EPSS: %w", err)
		}
		if len(rec) > 0 && strings.HasPrefix(rec[0], "#") {
			for _, f := range rec {
				if v, ok := strings.CutPrefix(f, "score_date:"); ok {
					date = v
				}
			}
			continue
		}
		if len(rec) < 2 || !strings.HasPrefix(rec[0], "CVE-") {
			continue // header row
		}
		if f, err := strconv.ParseFloat(rec[1], 64); err == nil {
			out[rec[0]] = f
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("EPSS: file contained no scores")
	}
	return out, date, nil
}

// NVDChange is one CVE returned by an NVD sync.
type NVDChange struct {
	CVE      string
	CVSS     CVSS
	HasCVSS  bool
	Rejected bool
}

// NVD's API allows at most 120 days between lastModStartDate and lastModEndDate.
const nvdMaxWindow = 120 * 24 * time.Hour

// NVDSync pages through NVD and calls fn for every CVE. With a zero since it
// downloads everything; otherwise only CVEs modified between since and until.
// progress, if set, is called after each page.
func NVDSync(ctx context.Context, apiKey string, since, until time.Time, fn func(NVDChange), progress func(done, total int)) error {
	if since.IsZero() {
		return nvdPages(ctx, apiKey, url.Values{}, fn, progress)
	}
	for start := since; start.Before(until); start = start.Add(nvdMaxWindow) {
		end := start.Add(nvdMaxWindow)
		if end.After(until) {
			end = until
		}
		q := url.Values{}
		q.Set("lastModStartDate", start.UTC().Format(nvdTime))
		q.Set("lastModEndDate", end.UTC().Format(nvdTime))
		if err := nvdPages(ctx, apiKey, q, fn, progress); err != nil {
			return err
		}
	}
	return nil
}

const nvdTime = "2006-01-02T15:04:05.000-07:00"

func nvdPages(ctx context.Context, apiKey string, q url.Values, fn func(NVDChange), progress func(done, total int)) error {
	const perPage = 2000 // NVD's maximum
	pace := 6 * time.Second
	header := http.Header{}
	if apiKey != "" {
		pace = time.Second
		header.Set("apiKey", apiKey)
	}
	q.Set("resultsPerPage", strconv.Itoa(perPage))

	for start, total := 0, 1; start < total; start += perPage {
		if start > 0 {
			if err := sleep(ctx, pace); err != nil {
				return err
			}
		}
		q.Set("startIndex", strconv.Itoa(start))
		var page nvdPage
		if err := withRetry(ctx, func() error {
			return httpx.GetJSON(ctx, nvdURL+"?"+q.Encode(), header, &page)
		}); err != nil {
			return fmt.Errorf("NVD (startIndex %d): %w", start, err)
		}
		total = page.TotalResults
		for _, v := range page.Vulnerabilities {
			c := NVDChange{CVE: v.CVE.ID, Rejected: v.CVE.VulnStatus == "Rejected"}
			c.CVSS, c.HasCVSS = v.CVE.Metrics.best()
			fn(c)
		}
		if progress != nil {
			progress(min(start+perPage, total), total)
		}
	}
	return nil
}

// withRetry retries transient failures (NVD returns 403/429/5xx or stops
// answering under load) with increasing waits, about 20 minutes in total, so
// a full download of every CVE survives an NVD slowdown.
func withRetry(ctx context.Context, f func() error) error {
	waits := []time.Duration{6 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 300 * time.Second, 300 * time.Second}
	var err error
	for i := 0; ; i++ {
		if err = f(); err == nil || i == len(waits) || ctx.Err() != nil {
			return err
		}
		if err := sleep(ctx, waits[i]); err != nil {
			return err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
