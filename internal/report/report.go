// Package report renders scan results for people (text) and machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/hardenkit/scan/internal/aistack"
	"github.com/hardenkit/scan/internal/finding"
	"github.com/hardenkit/scan/internal/issue"
	"github.com/hardenkit/scan/internal/kube"
)

// Result is everything one scan produced.
type Result struct {
	Target     string            `json:"target"`
	Packages   int               `json:"packages"`
	Upgrades   []finding.Upgrade `json:"upgrades"`
	Findings   []finding.Finding `json:"findings"`
	Sources    []string          `json:"sources"`
	Database   string            `json:"database_built,omitempty"` // when the prebuilt database was generated
	AIStack    *aistack.Report   `json:"ai_stack,omitempty"`
	Kubernetes *kube.Report      `json:"kubernetes,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
}

// configCounts is the header summary of configuration issues, e.g.
// " · 3 AI-stack issues · 5 Kubernetes issues".
func (r Result) configCounts() string {
	var b strings.Builder
	for _, s := range sections(r) {
		if len(s.issues) > 0 {
			fmt.Fprintf(&b, " · %d %s issues", len(s.issues), s.name)
		}
	}
	return b.String()
}

// JSON writes r as indented JSON.
func JSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// markdownRowLimit caps the findings table; GitHub step summaries are limited to 1 MiB.
const markdownRowLimit = 100

// Markdown writes a GitHub-flavored Markdown report, for CI step summaries and PR comments.
func Markdown(w io.Writer, r Result) error {
	exploited := 0
	for _, f := range r.Findings {
		if f.KEV != nil {
			exploited++
		}
	}
	fmt.Fprintf(w, "## hardenkit scan\n\n")
	fmt.Fprintf(w, "**%d packages · %d vulnerabilities", r.Packages, len(r.Findings))
	if exploited > 0 {
		fmt.Fprintf(w, " · %d exploited in the wild", exploited)
	}
	fmt.Fprint(w, r.configCounts())
	fmt.Fprintf(w, "** in `%s`\n\n", r.Target)
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "> [!WARNING]\n> %s\n\n", md(warn))
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No known vulnerabilities found.")
	} else {
		markdownFindings(w, r)
	}
	for _, sec := range sections(r) {
		markdownSection(w, sec)
	}
	fmt.Fprintf(w, "\n<sub>Data: %s</sub>\n", strings.Join(r.Sources, ", "))
	return nil
}

func markdownFindings(w io.Writer, r Result) {
	fmt.Fprint(w, "### Upgrade plan\n\n")
	fmt.Fprintln(w, "| Priority | Package | Installed | Upgrade to | Fixes |")
	fmt.Fprintln(w, "|:--|:--|:--|:--|--:|")
	for _, u := range r.Upgrades {
		to := "no fix yet"
		if u.UpgradeTo != "" {
			to = "`" + u.UpgradeTo + "`"
		}
		fixes := fmt.Sprint(u.Fixes)
		if u.Unfixed > 0 {
			fixes += fmt.Sprintf(" (+%d without a fix)", u.Unfixed)
		}
		fmt.Fprintf(w, "| %s | `%s` | `%s` | %s | %s |\n", u.Priority, md(u.Package.Name), md(u.Package.Version), to, fixes)
	}

	fmt.Fprint(w, "\n<details><summary>All findings</summary>\n\n")
	fmt.Fprintln(w, "| Priority | Vulnerability | Package | Fix | Severity | EPSS |")
	fmt.Fprintln(w, "|:--|:--|:--|:--|:--|--:|")
	for i, f := range r.Findings {
		if i == markdownRowLimit {
			fmt.Fprintf(w, "\n%d more not shown; run `hardenkit scan` locally for the full list.\n", len(r.Findings)-i)
			break
		}
		id := f.ID
		if strings.HasPrefix(id, "CVE-") {
			id = fmt.Sprintf("[%s](https://osv.dev/vulnerability/%s)", id, id)
		}
		if f.KEV != nil {
			id += " **(exploited)**"
		}
		fix := "no fix yet"
		if f.FixedIn != "" {
			fix = "`" + f.FixedIn + "`"
		}
		sev := f.Severity
		if f.CVSS != nil {
			sev = fmt.Sprintf("%s %.1f", sev, f.CVSS.Score)
		}
		epss := "–"
		if f.EPSS != nil {
			epss = fmt.Sprintf("%.1f%%", *f.EPSS*100)
		}
		fmt.Fprintf(w, "| %s | %s | `%s@%s` | %s | %s | %s |\n", f.Priority, id, md(f.Package.Name), md(f.Package.Version), fix, sev, epss)
	}
	fmt.Fprintln(w, "\n</details>")
}

// section is a group of configuration issues (AI stack, Kubernetes) with
// the inventory they were found in.
type section struct {
	title, inventoryTitle, name string
	inventory                   [][2]string
	issues                      []issue.Issue
}

func sections(r Result) []section {
	var out []section
	if a := r.AIStack; a != nil {
		if inv := inventoryLines(a); len(inv) > 0 || len(a.Issues) > 0 {
			out = append(out, section{"AI stack", "AI inventory", "AI-stack", inv, a.Issues})
		}
	}
	if k := r.Kubernetes; k != nil {
		out = append(out, section{"Kubernetes", "Kubernetes inventory", "Kubernetes", kubeLines(k), k.Issues})
	}
	return out
}

func markdownSection(w io.Writer, s section) {
	fmt.Fprintf(w, "\n### %s\n\n", s.title)
	if len(s.issues) > 0 {
		fmt.Fprintln(w, "| Severity | Issue | File | Fix |")
		fmt.Fprintln(w, "|:--|:--|:--|:--|")
		for i, is := range s.issues {
			if i == markdownRowLimit {
				fmt.Fprintf(w, "\n%d more not shown; run `hardenkit scan` locally for the full list.\n", len(s.issues)-i)
				break
			}
			fmt.Fprintf(w, "| %s | %s | `%s` | %s |\n", is.Severity, md(is.Title), md(location(is)), md(is.Fix))
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "No %s issues found.\n\n", s.name)
	}
	fmt.Fprintf(w, "<details><summary>%s</summary>\n\n", s.inventoryTitle)
	for _, line := range s.inventory {
		fmt.Fprintf(w, "- **%s:** %s\n", line[0], md(line[1]))
	}
	fmt.Fprintln(w, "\n</details>")
}

func location(is issue.Issue) string {
	if is.Line > 0 {
		return fmt.Sprintf("%s:%d", is.File, is.Line)
	}
	return is.File
}

// inventoryLines summarizes the AI inventory as (label, items) pairs.
func inventoryLines(a *aistack.Report) [][2]string {
	var out [][2]string
	var cat string
	var items []string
	flush := func() {
		if cat != "" {
			out = append(out, [2]string{cat, strings.Join(items, ", ")})
		}
	}
	for _, c := range a.Components {
		if c.Category != cat {
			flush()
			cat, items = c.Category, nil
		}
		items = append(items, strings.TrimSpace(c.Name+" "+strings.Join(c.Versions, ", ")))
	}
	flush()
	if len(a.MCPServers) > 0 {
		var s []string
		for _, m := range a.MCPServers {
			s = append(s, fmt.Sprintf("%s (%s)", m.Name, m.File))
		}
		out = append(out, [2]string{"MCP servers", strings.Join(s, ", ")})
	}
	if len(a.Models) > 0 {
		var s []string
		for _, m := range a.Models {
			s = append(s, fmt.Sprintf("%s (%s)", m.File, m.Format))
		}
		out = append(out, [2]string{"Model files", strings.Join(s, ", ")})
	}
	return out
}

// md escapes characters that would break a Markdown table cell.
func md(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "`", "'").Replace(s)
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
	fmt.Fprint(w, r.configCounts())
	fmt.Fprintln(w)

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "\nNo known vulnerabilities found.")
	} else if err := textFindings(w, r, verbose); err != nil {
		return err
	}
	for _, sec := range sections(r) {
		textSection(w, sec, verbose)
	}

	fmt.Fprintf(w, "\nData: %s", strings.Join(r.Sources, ", "))
	if r.Database != "" {
		fmt.Fprintf(w, " (database built %s)", r.Database)
	}
	fmt.Fprintln(w)
	return nil
}

func textFindings(w io.Writer, r Result, verbose bool) error {
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
	return nil
}

func textSection(w io.Writer, s section, verbose bool) {
	fmt.Fprintf(w, "\n%s\n", strings.ToUpper(s.title))
	for _, line := range s.inventory {
		fmt.Fprintf(w, "  %s: %s\n", line[0], line[1])
	}
	if len(s.issues) == 0 {
		fmt.Fprintf(w, "\nNo %s issues found.\n", s.name)
		return
	}
	fmt.Fprintln(w)
	low := 0
	for _, is := range s.issues {
		if is.Severity == "LOW" && !verbose {
			low++
			continue
		}
		fmt.Fprintf(w, "%-8s  %s\n", is.Severity, location(is))
		fmt.Fprintf(w, "          %s\n", is.Title)
		fmt.Fprintf(w, "          Fix: %s\n", is.Fix)
	}
	if low > 0 {
		fmt.Fprintf(w, "%d low-severity issues not shown; add -v to see them.\n", low)
	}
}

// kubeLines summarizes the Kubernetes inventory as (label, items) pairs.
func kubeLines(k *kube.Report) [][2]string {
	var out [][2]string
	if len(k.Resources) > 0 {
		counts := map[string]int{}
		var kinds []string
		for _, res := range k.Resources {
			if counts[res.Kind] == 0 {
				kinds = append(kinds, res.Kind)
			}
			counts[res.Kind]++
		}
		sort.Strings(kinds)
		var parts []string
		for _, kind := range kinds {
			parts = append(parts, fmt.Sprintf("%d %s", counts[kind], kind))
		}
		out = append(out, [2]string{"Resources", strings.Join(parts, ", ")})
	}
	if len(k.Charts) > 0 {
		out = append(out, [2]string{"Helm charts", strings.Join(k.Charts, ", ")})
	}
	if len(k.Images) > 0 {
		out = append(out, [2]string{"Images", strings.Join(k.Images, ", ") + " (scan each with: hardenkit scan IMAGE)"})
	}
	return out
}
