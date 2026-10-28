package vulndb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardenkit/scan/internal/httpx"
)

// DefaultURL is where the nightly build publishes the database.
const DefaultURL = "https://github.com/hardenkit/scan/releases/download/db/enrichment.json.gz"

// maxAge is how long a cached copy is used before downloading a newer one.
// The database is rebuilt daily.
const maxAge = 24 * time.Hour

// Load returns the database from source, which is an https URL or a local
// file path. URLs are cached in the user's cache directory and refreshed once
// a day. If a refresh fails but a cached copy exists, the stale copy is used
// and a warning is returned alongside it.
func Load(ctx context.Context, source string) (db *DB, warning string, err error) {
	if !strings.HasPrefix(source, "https://") && !strings.HasPrefix(source, "http://") {
		db, err := ReadFile(source)
		return db, "", err
	}

	cache, err := cachePath()
	if err != nil {
		return nil, "", err
	}
	if fi, err := os.Stat(cache); err == nil && time.Since(fi.ModTime()) < maxAge {
		if db, err := ReadFile(cache); err == nil {
			return db, "", nil
		}
	}

	if dlErr := download(ctx, source, cache); dlErr != nil {
		if db, err := ReadFile(cache); err == nil {
			return db, fmt.Sprintf("using cached vulnerability database (refresh failed: %v)", dlErr), nil
		}
		return nil, "", dlErr
	}
	db, err = ReadFile(cache)
	return db, "", err
}

func cachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hardenkit", "enrichment.json.gz"), nil
}

func download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", httpx.UserAgent)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download vulnerability database: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download vulnerability database: HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return fmt.Errorf("download vulnerability database: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Validate before replacing a good cached copy with a bad download.
	if _, err := ReadFile(tmp.Name()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
