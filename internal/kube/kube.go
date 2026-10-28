// Package kube checks Kubernetes manifests and Helm charts for settings that
// let a compromised container take over its node or the cluster: privileged
// pods, host namespaces and paths, missing Pod Security "restricted"
// settings, over-broad RBAC, and secrets committed to the repository.
package kube

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/hardenkit/scan/internal/issue"
)

// Report is the Kubernetes part of a scan.
type Report struct {
	Resources []Resource    `json:"resources"`
	Images    []string      `json:"images"` // container images the workloads run
	Charts    []string      `json:"charts"` // Helm charts rendered with their default values
	Issues    []issue.Issue `json:"issues"`
	Warnings  []string      `json:"-"`
}

// Resource is one Kubernetes object found in the manifests.
type Resource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
}

// Directories that hold installed dependencies rather than the project's own files.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true, "vendor": true,
}

const maxManifestSize = 5 << 20

// helmTimeout bounds rendering one chart.
const helmTimeout = 60 * time.Second

// Scan finds Kubernetes manifests under root (a directory or a single file)
// and checks them. Helm charts are rendered with `helm template` when helm is
// installed; otherwise they are skipped with a warning. It returns nil when
// root holds no Kubernetes resources.
func Scan(ctx context.Context, root string) (*Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	r := &Report{Resources: []Resource{}, Images: []string{}, Charts: []string{}, Issues: []issue.Issue{}}
	c := &checker{r: r, images: map[string]bool{}}

	if !info.IsDir() {
		if isYAML(root) {
			c.file(root, filepath.Base(root))
		}
	} else {
		helm, _ := exec.LookPath("helm")
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if p != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				// A Helm chart: its templates aren't valid YAML until rendered.
				if _, err := os.Stat(filepath.Join(p, "Chart.yaml")); err == nil {
					c.chart(ctx, helm, p, rel)
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && isYAML(p) {
				c.file(p, rel)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if len(r.Resources) == 0 && len(r.Charts) == 0 && len(r.Warnings) == 0 {
		return nil, nil
	}
	for img := range c.images {
		r.Images = append(r.Images, img)
	}
	sort.Strings(r.Images)
	issue.Sort(r.Issues)
	return r, nil
}

func isYAML(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

type checker struct {
	r      *Report
	images map[string]bool
}

func (c *checker) file(p, rel string) {
	info, err := os.Stat(p)
	if err != nil || info.Size() > maxManifestSize {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	c.documents(data, rel, true)
}

// documents checks every Kubernetes object in a multi-document YAML stream.
// Files that aren't YAML or hold no Kubernetes objects are ignored.
func (c *checker) documents(data []byte, rel string, withLines bool) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return // end of stream, or not YAML we can read (a template, another tool's file)
		}
		if len(doc.Content) == 0 {
			continue
		}
		node := doc.Content[0]
		line := 0
		if withLines {
			line = node.Line
		}
		var obj object
		if err := node.Decode(&obj); err != nil || obj.Kind == "" || obj.APIVersion == "" {
			continue
		}
		if obj.Kind == "List" {
			for i := range obj.Items {
				c.object(&obj.Items[i], rel, line)
			}
			continue
		}
		c.object(node, rel, line)
	}
}

func (c *checker) object(node *yaml.Node, rel string, line int) {
	var obj object
	if err := node.Decode(&obj); err != nil || obj.Kind == "" {
		return
	}
	res := Resource{Kind: obj.Kind, Name: obj.Metadata.Name, Namespace: obj.Metadata.Namespace, File: rel, Line: line}
	c.r.Resources = append(c.r.Resources, res)
	ref := obj.Kind + "/" + obj.Metadata.Name
	add := func(rule, severity, title, fix string) {
		c.r.Issues = append(c.r.Issues, issue.Issue{Rule: rule, Severity: severity, File: rel, Line: line, Title: ref + ": " + title, Fix: fix})
	}

	if spec := podSpecOf(node, obj.Kind); spec != nil {
		for _, ct := range append(append([]container{}, spec.InitContainers...), spec.Containers...) {
			if ct.Image != "" {
				c.images[ct.Image] = true
			}
		}
		checkPod(spec, add)
		return
	}
	switch obj.Kind {
	case "Role", "ClusterRole":
		var role struct {
			Rules []rule `yaml:"rules"`
		}
		if node.Decode(&role) == nil {
			checkRole(role.Rules, add)
		}
	case "RoleBinding", "ClusterRoleBinding":
		var b binding
		if node.Decode(&b) == nil {
			checkBinding(b, add)
		}
	case "Secret":
		var s struct {
			Data       map[string]string `yaml:"data"`
			StringData map[string]string `yaml:"stringData"`
			Type       string            `yaml:"type"`
		}
		if node.Decode(&s) == nil && hasValues(s.Data, s.StringData) && !strings.HasPrefix(s.Type, "helm.sh/") {
			add("k8s-secret-in-repo", "HIGH", "Secret with values committed to the repository",
				"Remove the values and rotate them; manage secrets with External Secrets, Sealed Secrets or SOPS, or create them out of band.")
		}
	}
}

func hasValues(maps ...map[string]string) bool {
	for _, m := range maps {
		for _, v := range m {
			if strings.TrimSpace(v) != "" {
				return true
			}
		}
	}
	return false
}

type object struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Items []yaml.Node `yaml:"items"`
}

// chart renders a Helm chart with its default values and checks the output.
func (c *checker) chart(ctx context.Context, helm, dir, rel string) {
	if rel == "." {
		rel = filepath.Base(dir)
	}
	if helm == "" {
		c.r.Warnings = append(c.r.Warnings, fmt.Sprintf("Helm chart %s not checked: install helm to render it", rel))
		return
	}
	ctx, cancel := context.WithTimeout(ctx, helmTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, helm, "template", "hardenkit-scan", dir)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		c.r.Warnings = append(c.r.Warnings, fmt.Sprintf("Helm chart %s not checked: %s", rel, msg))
		return
	}
	c.r.Charts = append(c.r.Charts, rel)

	// Each rendered document starts with "# Source: <chart>/templates/x.yaml";
	// report issues against that template.
	for _, chunk := range splitDocuments(stdout.Bytes()) {
		file := rel
		if src := sourceOf(chunk); src != "" {
			if _, after, ok := strings.Cut(src, "/"); ok {
				file = path.Join(rel, after)
			}
		}
		c.documents(chunk, file, false)
	}
}

func splitDocuments(out []byte) [][]byte {
	var docs [][]byte
	for _, d := range bytes.Split(out, []byte("\n---")) {
		if len(bytes.TrimSpace(d)) > 0 {
			docs = append(docs, d)
		}
	}
	return docs
}

func sourceOf(doc []byte) string {
	for _, line := range strings.Split(string(doc), "\n") {
		if src, ok := strings.CutPrefix(strings.TrimSpace(line), "# Source: "); ok {
			return src
		}
	}
	return ""
}
