// Package osv matches packages against the OSV.dev vulnerability database.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/hardenkit/scan/internal/httpx"
)

const (
	baseURL   = "https://api.osv.dev/v1"
	batchSize = 1000 // OSV's documented maximum per querybatch call
	workers   = 8
)

// Vuln is the subset of an OSV record the scanner uses.
type Vuln struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Aliases          []string         `json:"aliases"`
	Affected         []Affected       `json:"affected"`
	References       []Reference      `json:"references"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

type Affected struct {
	Package          AffectedPackage  `json:"package"`
	Ranges           []Range          `json:"ranges"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

type AffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

// CVE returns the record's CVE ID, from its ID or aliases, or "".
func (v *Vuln) CVE() string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}

// Severity returns the advisory's own severity label (GHSA style), upper-cased, or "".
func (v *Vuln) Severity() string {
	s := v.DatabaseSpecific.Severity
	if s == "" {
		for _, a := range v.Affected {
			if a.DatabaseSpecific.Severity != "" {
				s = a.DatabaseSpecific.Severity
				break
			}
		}
	}
	s = strings.ToUpper(s)
	if s == "MODERATE" {
		s = "MEDIUM"
	}
	return s
}

// FixedVersions returns every "fixed" version listed for the named package.
// With an ecosystem (e.g. "Debian:13"), only that ecosystem's entries count,
// so one Debian release's fix isn't offered for another.
func (v *Vuln) FixedVersions(pkgName, ecosystem string) []string {
	var out []string
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Name, pkgName) {
			continue
		}
		if ecosystem != "" && a.Package.Ecosystem != ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && r.Type != "GIT" {
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

// Query returns the OSV IDs affecting each target, keyed by Target.Key.
func Query(ctx context.Context, targets []Target) (map[string][]string, error) {
	type pkg struct {
		PURL      string `json:"purl,omitempty"`
		Ecosystem string `json:"ecosystem,omitempty"`
		Name      string `json:"name,omitempty"`
	}
	type query struct {
		Package pkg    `json:"package"`
		Version string `json:"version,omitempty"`
	}
	type result struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}

	var actions, rest []Target
	for _, t := range targets {
		switch {
		case t.Ecosystem != ActionsEcosystem:
			rest = append(rest, t)
		case t.Version != "":
			actions = append(actions, t)
		}
	}
	targets = rest
	out, err := queryActions(ctx, actions)
	if err != nil {
		return nil, err
	}
	for start := 0; start < len(targets); start += batchSize {
		end := min(start+batchSize, len(targets))
		chunk := targets[start:end]

		body := struct {
			Queries []query `json:"queries"`
		}{}
		for _, t := range chunk {
			if t.Ecosystem != "" {
				body.Queries = append(body.Queries, query{Package: pkg{Ecosystem: t.Ecosystem, Name: t.Name}, Version: t.Version})
			} else {
				body.Queries = append(body.Queries, query{Package: pkg{PURL: t.PURL}})
			}
		}
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/querybatch", bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		var resp struct {
			Results []result `json:"results"`
		}
		if err := httpx.Do(req, &resp); err != nil {
			return nil, err
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				out[chunk[i].Key] = append(out[chunk[i].Key], v.ID)
			}
		}
	}
	return out, nil
}

// queryActions matches GitHub Actions. OSV doesn't match versions in this
// ecosystem, so each action's advisories are fetched by name and its tag is
// checked against their ranges here.
func queryActions(ctx context.Context, targets []Target) (map[string][]string, error) {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
		out      = map[string][]string{}
		jobs     = make(chan Target)
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				body, _ := json.Marshal(map[string]any{"package": map[string]string{"ecosystem": t.Ecosystem, "name": t.Name}})
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/query", bytes.NewReader(body))
				var resp struct {
					Vulns []Vuln `json:"vulns"`
				}
				if err == nil {
					req.Header.Set("Content-Type", "application/json")
					err = httpx.Do(req, &resp)
				}
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				for _, v := range resp.Vulns {
					var ranges []Range
					for _, a := range v.Affected {
						if a.Package.Ecosystem == t.Ecosystem && strings.EqualFold(a.Package.Name, t.Name) {
							ranges = append(ranges, a.Ranges...)
						}
					}
					if actionAffected(t.Version, ranges) {
						out[t.Key] = append(out[t.Key], v.ID)
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	return out, firstErr
}

// Fetch downloads the full records for ids, in parallel.
func Fetch(ctx context.Context, ids []string) (map[string]*Vuln, error) {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
		out      = map[string]*Vuln{}
		jobs     = make(chan string)
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				var v Vuln
				err := httpx.GetJSON(ctx, baseURL+"/vulns/"+id, nil, &v)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				} else if err == nil {
					out[id] = &v
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	return out, firstErr
}

// NormalizePURL strips qualifiers and subpaths, which OSV does not match on
// and which can make a whole batch fail.
func NormalizePURL(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}
