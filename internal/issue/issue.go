// Package issue is the shared shape of configuration findings (AI stack,
// Kubernetes, GitHub Actions): a rule that matched a file, with a severity
// and a fix.
package issue

import "sort"

// Issue is one risky setting, file or line of code.
type Issue struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"` // CRITICAL, HIGH, MEDIUM or LOW
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Title    string `json:"title"`
	Fix      string `json:"fix"`
}

// Sort orders issues by severity (highest first), then file and line.
func Sort(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if ra, rb := rank(a.Severity), rank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

func rank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}
