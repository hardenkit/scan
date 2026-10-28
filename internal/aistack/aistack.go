// Package aistack inventories the AI parts of a project (LLM SDKs, agent
// frameworks, vector databases, MCP servers, model files) and flags the
// risky ones: secrets in MCP configs, unpinned MCP servers, model files that
// run code when loaded, and code that turns those protections off.
package aistack

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Report is the AI-stack part of a scan.
type Report struct {
	Components []Component `json:"components"`
	MCPServers []MCPServer `json:"mcp_servers"`
	Models     []Model     `json:"models"`
	Issues     []Issue     `json:"issues"`
}

// Issue is one risky configuration, model file or line of code.
type Issue struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"` // CRITICAL, HIGH, MEDIUM or LOW
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Title    string `json:"title"`
	Fix      string `json:"fix"`
}

// MCPServer is one server entry in an MCP client config.
type MCPServer struct {
	Name    string `json:"name"`
	File    string `json:"file"`
	Command string `json:"command,omitempty"` // local (stdio) servers
	URL     string `json:"url,omitempty"`     // remote servers
}

// Model is one model weights file.
type Model struct {
	File   string `json:"file"`
	Format string `json:"format"`
	Size   int64  `json:"size"`
}

// New returns an empty report; its lists encode as [] rather than null.
func New() *Report {
	return &Report{Components: []Component{}, MCPServers: []MCPServer{}, Models: []Model{}, Issues: []Issue{}}
}

// Directories that hold installed dependencies or build output rather than
// the project's own files.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, ".tox": true, "site-packages": true, "vendor": true,
}

// Scan walks the directory root (or checks the single file root) for MCP
// configs, model files and risky code. File paths in the result are relative
// to root. Unreadable files are skipped; only a failure to walk root at all
// is returned as an error.
func Scan(ctx context.Context, root string) (*Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	r := New()
	base := root
	if !info.IsDir() {
		base = filepath.Dir(root)
	}
	check := func(path string, d fs.DirEntry) {
		rel, err := filepath.Rel(base, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		switch {
		case isMCPConfig(rel):
			checkMCP(r, path, rel)
		case modelFormat(path) != "":
			checkModel(r, path, rel)
		case strings.HasSuffix(path, ".py"):
			checkSource(r, path, rel)
		}
	}

	if !info.IsDir() {
		check(root, fs.FileInfoToDirEntry(info))
	} else {
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entry; keep going
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				if path != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				check(path, d)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sort.SliceStable(r.Issues, func(i, j int) bool {
		a, b := r.Issues[i], r.Issues[j]
		if ra, rb := rank(a.Severity), rank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return r, nil
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
