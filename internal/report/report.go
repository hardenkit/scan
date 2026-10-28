// Package report renders scan results for people (text) and machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/hardenkit/scan/internal/finding"
)

// Result is everything one scan produced.
type Result struct {
	Target   string            `json:"target"`
	Packages int               `json:"packages"`
	Upgrades []finding.Upgrade `json:"upgrades"`
	Findings []finding.Finding `json:"findings"`
	Sources  []string          `json:"sources"`
	Warnings []string          `json:"warnings,omitempty"`
}

// JSON writes r as indented JSON.
func JSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text writes a ranked, human-readable report.
func Text(w io.Writer, r Result, verbose bool) error {
	exploited := 0
	for _, f := range r.Findings {
		if f.KEV != nil {
			exploited++
		}
	}
	fmt.Fprintf(w, "\nhardenkit scan · %s\n", r.Target)
	fmt.Fprintf(w, "%d packages · %d vulnerabilities", r.Packages, len(r.Findings))
	if exploited > 0 {
		fmt.Fprintf(w, " · %d exploited in the wild", exploited)
	}
	fmt.Fprintln(w)

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "\nNo known vulnerabilities found.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nUPGRADE PLAN\t\t\t\t\t")
	fmt.Fprintln(tw, "PRIORITY\tPACKAGE\tINSTALLED\tUPGRADE TO\tFIXES\t")
	for _, u := range r.Upgrades {
		to := u.UpgradeTo
		if to == "" {
			to = "no fix yet"
		}
		fixes := fmt.Sprintf("%d", u.Fixes)
		if u.Unfixed > 0 {
			fixes += fmt.Sprintf(" (%d without a fix)", u.Unfixed)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t\n", u.Priority, u.Package.Name, u.Package.Version, to, fixes)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(tw, "\nPRIORITY\tVULNERABILITY\tPACKAGE\tINSTALLED\tFIX\tSEVERITY\tEPSS\t")
	for _, f := range r.Findings {
		fix := f.FixedIn
		if fix == "" {
			fix = "no fix yet"
		}
		sev := f.Severity
		if f.CVSS != nil {
			sev = fmt.Sprintf("%s %.1f", sev, f.CVSS.Score)
		}
		epss := "-"
		if f.EPSS != nil {
			epss = fmt.Sprintf("%.1f%%", *f.EPSS*100)
		}
		id := f.ID
		if f.KEV != nil {
			id += " (KEV)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			f.Priority, id, f.Package.Name, f.Package.Version, fix, sev, epss)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if verbose {
		for _, f := range r.Findings {
			fmt.Fprintf(w, "\n%s · %s %s\n", f.ID, f.Package.Name, f.Package.Version)
			if f.Summary != "" {
				fmt.Fprintf(w, "  %s\n", f.Summary)
			}
			if f.KEV != nil {
				fmt.Fprintf(w, "  Actively exploited (CISA KEV, added %s)", f.KEV.DateAdded)
				if f.KEV.Ransomware {
					fmt.Fprint(w, ", used in ransomware campaigns")
				}
				fmt.Fprintln(w)
			}
			if len(f.Package.Locations) > 0 {
				fmt.Fprintf(w, "  Found in: %s\n", strings.Join(f.Package.Locations, ", "))
			}
			fmt.Fprintf(w, "  Advisories: %s\n", strings.Join(f.Advisories, ", "))
			for _, ref := range f.References {
				fmt.Fprintf(w, "  %s\n", ref)
			}
		}
	}

	fmt.Fprintf(w, "\nData: %s\n", strings.Join(r.Sources, ", "))
	return nil
}
