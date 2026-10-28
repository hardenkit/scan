// Package vulndb is the prebuilt enrichment database: CISA KEV, EPSS and NVD
// CVSS for every CVE, built nightly so scans don't depend on NVD's rate limits.
//
// The file is gzipped JSON. Field names are short because there are ~400k
// entries; Schema is bumped on any incompatible change.
package vulndb

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hardenkit/scan/internal/enrich"
)

// Schema is the file format version this build reads and writes.
const Schema = 1

// DB is the whole enrichment database.
type DB struct {
	Schema    int    `json:"schema"`
	Generated string `json:"generated"` // RFC 3339, when the file was built
	// NVDSyncedTo is the end of the last NVD modification window fetched;
	// the next build only asks NVD for changes after it.
	NVDSyncedTo string            `json:"nvd_synced_to"`
	EPSSDate    string            `json:"epss_date"`
	CVEs        map[string]*Entry `json:"cves"`
}

// Entry is what's known about one CVE. Absent fields mean "no data".
type Entry struct {
	Score       float64          `json:"s,omitempty"`
	Severity    string           `json:"sv,omitempty"`
	Vector      string           `json:"v,omitempty"`
	CVSSVersion string           `json:"cv,omitempty"`
	EPSS        float64          `json:"e,omitempty"`
	KEV         *enrich.KEVEntry `json:"k,omitempty"`
}

// New returns an empty database.
func New() *DB { return &DB{Schema: Schema, CVEs: map[string]*Entry{}} }

// Entry returns the entry for cve, creating it if needed.
func (db *DB) Entry(cve string) *Entry {
	e, ok := db.CVEs[cve]
	if !ok {
		e = &Entry{}
		db.CVEs[cve] = e
	}
	return e
}

// Prune drops entries with no data left (e.g. a CVE that lost its EPSS score
// and has no CVSS).
func (db *DB) Prune() {
	for k, e := range db.CVEs {
		if *e == (Entry{}) {
			delete(db.CVEs, k)
		}
	}
}

// Lookup returns KEV, EPSS and CVSS data for cves in the shapes the finding
// package takes.
func (db *DB) Lookup(cves []string) (map[string]enrich.KEVEntry, map[string]float64, map[string]enrich.CVSS) {
	kev := map[string]enrich.KEVEntry{}
	epss := map[string]float64{}
	cvss := map[string]enrich.CVSS{}
	for _, id := range cves {
		e, ok := db.CVEs[id]
		if !ok {
			continue
		}
		if e.KEV != nil {
			kev[id] = *e.KEV
		}
		if e.EPSS > 0 {
			epss[id] = e.EPSS
		}
		if e.Severity != "" || e.Score > 0 {
			cvss[id] = enrich.CVSS{Version: e.CVSSVersion, Score: e.Score, Severity: e.Severity, Vector: e.Vector}
		}
	}
	return kev, epss, cvss
}

// Read decodes a gzipped database.
func Read(r io.Reader) (*DB, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("vulndb: %w", err)
	}
	defer gz.Close()
	db := New()
	if err := json.NewDecoder(gz).Decode(db); err != nil {
		return nil, fmt.Errorf("vulndb: %w", err)
	}
	if db.Schema != Schema {
		return nil, fmt.Errorf("vulndb: file has schema %d, this build reads %d (upgrade hardenkit)", db.Schema, Schema)
	}
	if db.CVEs == nil {
		db.CVEs = map[string]*Entry{}
	}
	return db, nil
}

// ReadFile decodes the gzipped database at path.
func ReadFile(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// WriteFile writes db to path atomically, gzipped.
func (db *DB) WriteFile(path string) error {
	db.Schema = Schema
	db.Generated = time.Now().UTC().Format(time.RFC3339)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vulndb-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	gz, err := gzip.NewWriterLevel(tmp, gzip.BestCompression)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(gz).Encode(db); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
