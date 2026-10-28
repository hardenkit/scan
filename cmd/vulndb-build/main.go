// Command vulndb-build builds the enrichment database the CLI downloads:
// CVSS from NVD, plus CISA KEV and FIRST EPSS for every CVE.
//
// With --previous it only asks NVD for CVEs modified since that build, which
// takes minutes; without it, it downloads all of NVD (~25 minutes with a key).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/hardenkit/scan/internal/enrich"
	"github.com/hardenkit/scan/internal/vulndb"
)

// overlap re-fetches a little before the previous sync point, so a CVE
// modified while the last build was running isn't missed.
const overlap = 2 * time.Hour

func main() {
	previous := flag.String("previous", "", "previous database to update incrementally (optional)")
	out := flag.String("out", "enrichment.json.gz", "output path")
	window := flag.Duration("window", 0, "without --previous, only fetch NVD changes from this long ago (for testing; produces a partial database)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, *previous, *out, *window); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, previous, out string, window time.Duration) error {
	apiKey := os.Getenv("HARDENKIT_NVD_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "warning: HARDENKIT_NVD_API_KEY is not set; NVD will be about 6x slower")
	}

	db := vulndb.New()
	if previous != "" {
		var err error
		if db, err = vulndb.ReadFile(previous); err != nil {
			return fmt.Errorf("read previous database: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Previous database: %d CVEs, NVD synced to %s\n", len(db.CVEs), db.NVDSyncedTo)
	}

	until := time.Now().UTC()
	var since time.Time
	switch {
	case db.NVDSyncedTo != "":
		t, err := time.Parse(time.RFC3339, db.NVDSyncedTo)
		if err != nil {
			return fmt.Errorf("previous database has a bad nvd_synced_to: %w", err)
		}
		since = t.Add(-overlap)
	case window > 0:
		since = until.Add(-window)
	}
	if since.IsZero() {
		fmt.Fprintln(os.Stderr, "NVD: full download")
	} else {
		fmt.Fprintf(os.Stderr, "NVD: changes since %s\n", since.Format(time.RFC3339))
	}

	var updated, rejected int
	err := enrich.NVDSync(ctx, apiKey, since, until, func(c enrich.NVDChange) {
		switch {
		case c.Rejected:
			if e, ok := db.CVEs[c.CVE]; ok {
				e.Score, e.Severity, e.Vector, e.CVSSVersion = 0, "", "", ""
			}
			rejected++
		case c.HasCVSS:
			e := db.Entry(c.CVE)
			e.Score, e.Severity, e.Vector, e.CVSSVersion = c.CVSS.Score, c.CVSS.Severity, c.CVSS.Vector, c.CVSS.Version
			updated++
		}
	}, func(done, total int) {
		fmt.Fprintf(os.Stderr, "  NVD %d/%d\n", done, total)
	})
	if err != nil {
		return err
	}
	db.NVDSyncedTo = until.Format(time.RFC3339)

	kev, err := enrich.KEV(ctx)
	if err != nil {
		return err
	}
	for _, e := range db.CVEs {
		e.KEV = nil // KEV and EPSS are replaced in full on every build
	}
	for id, k := range kev {
		db.Entry(id).KEV = &k
	}

	epss, date, err := enrich.EPSSAll(ctx)
	if err != nil {
		return err
	}
	for _, e := range db.CVEs {
		e.EPSS = 0
	}
	for id, s := range epss {
		db.Entry(id).EPSS = s
	}
	db.EPSSDate = date

	db.Prune()
	if err := db.WriteFile(out); err != nil {
		return err
	}
	fi, err := os.Stat(out)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Wrote %s: %d CVEs (%d CVSS updated, %d rejected, %d in KEV, %d EPSS scores dated %s), %.1f MB\n",
		out, len(db.CVEs), updated, rejected, len(kev), len(epss), date, float64(fi.Size())/1e6)
	return nil
}
