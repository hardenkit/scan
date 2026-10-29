// Package ghactions checks GitHub Actions workflows and composite actions for
// the settings that let an outsider run code in CI with the repository's
// secrets: script injection through ${{ }} expressions, pull_request_target
// jobs that run pull request code, third-party actions that aren't pinned to
// a commit, over-broad GITHUB_TOKEN permissions and secrets written into
// the workflow.
package ghactions

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/hardenkit/scan/internal/issue"
	"github.com/hardenkit/scan/internal/secret"
)

// Report is the GitHub Actions part of a scan.
type Report struct {
	Workflows []Workflow    `json:"workflows"`
	Actions   []string      `json:"actions"` // actions and reusable workflows used from other repositories
	Issues    []issue.Issue `json:"issues"`
}

// Workflow is one workflow file or composite action.
type Workflow struct {
	File     string   `json:"file"`
	Name     string   `json:"name,omitempty"`
	Triggers []string `json:"triggers,omitempty"` // empty for composite actions
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true, "vendor": true,
}

const maxFileSize = 1 << 20

// Scan finds workflows (.github/workflows/*.yml) and composite actions
// (action.yml) under root and checks them. It returns nil when there are none.
func Scan(ctx context.Context, root string) (*Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	r := &Report{Workflows: []Workflow{}, Actions: []string{}, Issues: []issue.Issue{}}
	c := &checker{r: r, actions: map[string]bool{}, pinned: map[string]bool{}}
	if !info.IsDir() {
		c.file(root, filepath.ToSlash(root))
	} else {
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				if p != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if d.Type().IsRegular() {
				c.file(p, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(r.Workflows) == 0 {
		return nil, nil
	}
	for a := range c.actions {
		r.Actions = append(r.Actions, a)
	}
	sort.Strings(r.Actions)
	issue.Sort(r.Issues)
	return r, nil
}

type checker struct {
	r       *Report
	actions map[string]bool
	pinned  map[string]bool // file|action already checked, so each is reported once per file
	rel     string
}

func (c *checker) file(p, rel string) {
	base := strings.ToLower(filepath.Base(rel))
	abs, _ := filepath.Abs(p) // so scanning .github itself still finds its workflows
	workflow := strings.Contains(strings.ToLower(filepath.ToSlash(abs)), "/.github/workflows/") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
	action := base == "action.yml" || base == "action.yaml"
	if !workflow && !action {
		return
	}
	info, err := os.Stat(p)
	if err != nil || info.Size() > maxFileSize {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return
	}
	root := doc.Content[0]
	c.rel = rel
	if workflow {
		c.workflow(root, rel)
	} else {
		c.composite(root, rel)
	}
}

// Triggers that run with the base repository's secrets and a write token
// even when an outsider starts them (a fork's pull request, an issue or a
// comment).
var privilegedTriggers = map[string]bool{
	"pull_request_target": true, "issue_comment": true, "issues": true,
	"discussion": true, "discussion_comment": true, "workflow_run": true,
}

func (c *checker) workflow(root *yaml.Node, rel string) {
	jobs := get(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return
	}
	wf := Workflow{File: rel, Name: scalar(get(root, "name")), Triggers: triggers(get(root, "on"))}
	c.r.Workflows = append(c.r.Workflows, wf)
	privileged := false
	for _, t := range wf.Triggers {
		if privilegedTriggers[t] {
			privileged = true
		}
	}
	add := c.adder(rel)

	topPerms := get(root, "permissions")
	checkPermissions(topPerms, "workflow", privileged, add)
	checkEnv(get(root, "env"), add)

	byID := map[string]*yaml.Node{}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		byID[jobs.Content[i].Value] = jobs.Content[i+1]
	}
	unscoped := false
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		id, job := jobs.Content[i].Value, jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		perms := get(job, "permissions")
		if perms == nil {
			unscoped = true
		}
		checkPermissions(perms, fmt.Sprintf("job %q", id), privileged, add)
		checkEnv(get(job, "env"), add)
		if u := get(job, "uses"); u != nil { // a reusable workflow
			c.uses(u, add)
			if s := get(job, "secrets"); scalar(s) == "inherit" && !strings.HasPrefix(u.Value, "./") {
				add("gha-secrets-inherit", "MEDIUM", s.Line, fmt.Sprintf("job %q passes every secret to %s", id, u.Value),
					"List only the secrets the called workflow needs under secrets: instead of secrets: inherit.")
			}
			continue
		}
		c.steps(get(job, "steps"), jobContext{
			where:      fmt.Sprintf("job %q", id),
			triggers:   privilegedOf(wf.Triggers),
			privileged: privileged,
			gated:      gated(byID, id, map[string]bool{}),
			write:      canWrite(perms, topPerms),
		}, add)
	}
	if topPerms == nil && unscoped {
		line := 1
		if on := key(root, "on"); on != nil {
			line = on.Line
		}
		add("gha-default-permissions", "LOW", line, "workflow doesn't set permissions, so GITHUB_TOKEN gets the repository default (write access on older repositories)",
			"Add permissions: {contents: read} at the top and grant more per job only where needed.")
	}
}

func (c *checker) composite(root *yaml.Node, rel string) {
	runs := get(root, "runs")
	if strings.ToLower(scalar(get(runs, "using"))) != "composite" {
		return
	}
	c.r.Workflows = append(c.r.Workflows, Workflow{File: rel, Name: scalar(get(root, "name"))})
	c.steps(get(runs, "steps"), jobContext{where: "step"}, c.adder(rel))
}

// jobContext is what the step checks need to know about the job.
type jobContext struct {
	where      string   // "job \"build\"", or "step" in a composite action
	triggers   []string // the privileged triggers of the workflow
	privileged bool
	gated      bool // an if: condition checks who started the run
	write      bool // GITHUB_TOKEN may have write access
}

// risk describes what pull request code can reach in the job.
func (j jobContext) risk() string {
	s := "with the repository's secrets"
	if j.write {
		s += " and a write token"
	}
	if j.gated {
		s += " (after an if: check on who triggered it; code pushed after that check still runs)"
	}
	return s
}

// gate matches if: conditions that check who triggered a run or that a
// maintainer added a label.
var gate = regexp.MustCompile(`author_association|github\.(actor|triggering_actor)\b|\.labels\b|github\.event\.label\.name|github\.event\.review\.state`)

// gated reports whether a job, or a job it needs, has an if: that checks who
// triggered the run.
func gated(jobs map[string]*yaml.Node, id string, seen map[string]bool) bool {
	job := jobs[id]
	if job == nil || seen[id] {
		return false
	}
	seen[id] = true
	if gate.MatchString(scalar(get(job, "if"))) {
		return true
	}
	needs := get(job, "needs")
	if needs == nil {
		return false
	}
	if needs.Kind == yaml.ScalarNode {
		return gated(jobs, needs.Value, seen)
	}
	for _, n := range needs.Content {
		if gated(jobs, n.Value, seen) {
			return true
		}
	}
	return false
}

// canWrite reports whether GITHUB_TOKEN may have write access in a job.
// Without permissions the repository default applies, which may be write.
func canWrite(job, workflow *yaml.Node) bool {
	p := job
	if p == nil {
		p = workflow
	}
	if p == nil {
		return true
	}
	if p.Kind == yaml.ScalarNode {
		return p.Value == "write-all"
	}
	for i := 1; i < len(p.Content); i += 2 {
		if p.Content[i].Value == "write" {
			return true
		}
	}
	return false
}

type addFunc func(rule, severity string, line int, title, fix string)

func (c *checker) adder(rel string) addFunc {
	return func(rule, severity string, line int, title, fix string) {
		c.r.Issues = append(c.r.Issues, issue.Issue{Rule: rule, Severity: severity, File: rel, Line: line, Title: title, Fix: fix})
	}
}

func (c *checker) steps(steps *yaml.Node, job jobContext, add addFunc) {
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return
	}
	where, privileged := job.where, job.privileged
	runsCode := "CRITICAL"
	if job.gated {
		runsCode = "HIGH"
	}
	var checkout *yaml.Node // the step that checked out pull request code
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		checkEnv(get(step, "env"), add)
		uses := get(step, "uses")
		run := get(step, "run")

		if checkout != nil && (run != nil || (uses != nil && strings.HasPrefix(uses.Value, "./"))) {
			add("gha-untrusted-checkout", runsCode, checkout.Line,
				fmt.Sprintf("%s checks out pull request code and runs it on %s, %s", where, strings.Join(job.triggers, ", "), job.risk()),
				"Build and test pull requests on the pull_request trigger. If results must be posted back, upload them as an artifact and act on them in a separate workflow_run job that never runs the code.")
			checkout = nil
		}
		if run != nil {
			injection(run, where, privileged, add)
			if privileged && prCheckoutCmd.MatchString(run.Value) && checkout == nil {
				checkout = run
			}
			if pipeToShell.MatchString(run.Value) {
				add("gha-remote-script", "LOW", run.Line, where+" pipes a downloaded script into a shell",
					"Download the script, check it against a known checksum, then run it; or install a pinned release.")
			}
		}
		if uses == nil {
			continue
		}
		c.uses(uses, add)
		with := get(step, "with")
		name := strings.ToLower(actionName(uses.Value))
		if name == "actions/github-script" {
			if s := get(with, "script"); s != nil {
				injection(s, where, privileged, add)
			}
		}
		if name == "actions/checkout" && privileged && untrustedRef.MatchString(scalar(get(with, "ref"))) {
			checkout = get(with, "ref")
		}
		if with != nil && with.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(with.Content); i += 2 {
				k, v := with.Content[i], with.Content[i+1]
				if v.Kind == yaml.ScalarNode && !cacheKey.MatchString(k.Value) && secret.Literal(k.Value, v.Value) {
					add("gha-hardcoded-secret", "HIGH", v.Line, fmt.Sprintf("%s passes a literal secret to %s (input %s)", where, uses.Value, k.Value),
						"Store the value as an Actions secret and pass ${{ secrets.NAME }}, then rotate it.")
				}
			}
		}
	}
	if checkout != nil {
		severity := "HIGH"
		if job.gated {
			severity = "MEDIUM"
		}
		add("gha-untrusted-checkout", severity, checkout.Line,
			fmt.Sprintf("%s checks out pull request code on %s, %s", where, strings.Join(job.triggers, ", "), job.risk()),
			"Don't check out the pull request head in privileged workflows; a build script, config file or local action from the pull request can take over the job.")
	}
}

func privilegedOf(triggers []string) []string {
	var out []string
	for _, t := range triggers {
		if privilegedTriggers[t] {
			out = append(out, t)
		}
	}
	return out
}

var (
	expression = regexp.MustCompile(`\$\{\{(.*?)\}\}`)
	// Context values anyone who can open an issue, comment or pull request controls.
	untrustedContext = regexp.MustCompile(`\bgithub\.(head_ref|event\.(` +
		`(issue|pull_request|discussion)\.(title|body)|` +
		`(comment|review|review_comment)\.body|` +
		`pull_request\.head\.(ref|label|repo\.default_branch)|` +
		`head_commit\.(message|author\.(name|email))|` +
		`commits(\[[^\]]*\]|\.\*)\.(message|author\.(name|email))|` +
		`pages(\[[^\]]*\]|\.\*)\.page_name|` +
		`workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(name|email))|pull_requests(\[[^\]]*\]|\.\*)\.head\.ref)` +
		`))\b`)
	untrustedRef  = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head_(sha|branch)|github\.event\.number`)
	prCheckoutCmd = regexp.MustCompile(`\bgh pr checkout\b|git (fetch|pull)\b[^\n]*(pull/|head\.(sha|ref))`)
	cacheKey      = regexp.MustCompile(`(?i)^(key|restore-keys|cache-key|[\w-]*key-prefix)$`)
	pipeToShell   = regexp.MustCompile(`\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b`)
)

// injection reports ${{ }} expressions in a script that expand to text an
// outsider controls: GitHub pastes them into the script before it runs.
func injection(node *yaml.Node, where string, privileged bool, add addFunc) {
	severity := "HIGH"
	if privileged {
		severity = "CRITICAL"
	}
	seen := map[string]bool{}
	for _, m := range expression.FindAllStringSubmatchIndex(node.Value, -1) {
		expr := strings.TrimSpace(node.Value[m[2]:m[3]])
		ctx := untrustedContext.FindString(expr)
		if ctx == "" || seen[ctx] {
			continue
		}
		seen[ctx] = true
		add("gha-script-injection", severity, lineAt(node, m[0]),
			fmt.Sprintf("%s pastes ${{ %s }} into a script; anyone who can set it can run commands in the job", where, ctx),
			fmt.Sprintf("Pass it through an environment variable (env: VALUE: ${{ %s }}) and use \"$VALUE\" in the script.", ctx))
	}
}

// lineAt returns the file line of byte offset off in a scalar's value.
func lineAt(node *yaml.Node, off int) int {
	switch node.Style {
	case yaml.LiteralStyle:
		return node.Line + 1 + strings.Count(node.Value[:off], "\n")
	case yaml.FoldedStyle:
		return node.Line + 1
	}
	return node.Line
}

var sha = regexp.MustCompile(`^[0-9a-f]{40}$`)

// uses records an action reference and reports it when it isn't pinned.
func (c *checker) uses(node *yaml.Node, add addFunc) {
	ref := strings.TrimSpace(node.Value)
	if ref == "" || strings.HasPrefix(ref, "./") || strings.Contains(ref, "${{") || c.pinned[c.rel+"|"+ref] {
		return
	}
	c.pinned[c.rel+"|"+ref] = true
	if img, ok := strings.CutPrefix(ref, "docker://"); ok {
		c.actions[ref] = true
		if !strings.Contains(img, "@sha256:") {
			add("gha-unpinned-action", "MEDIUM", node.Line, fmt.Sprintf("uses container %s without a digest", img),
				"Pin the image by digest (docker://image@sha256:...) so a new push can't change what runs.")
		}
		return
	}
	name, version, _ := strings.Cut(ref, "@")
	c.actions[ref] = true
	owner, _, _ := strings.Cut(name, "/")
	if owner = strings.ToLower(owner); owner == "actions" || owner == "github" {
		return // maintained by GitHub, whose runner already trusts it
	}
	if sha.MatchString(version) {
		return
	}
	what := "tag " + version
	if version == "" {
		what = "no version"
	} else if !versionTag.MatchString(version) {
		what = "branch " + version
	}
	add("gha-unpinned-action", "MEDIUM", node.Line, fmt.Sprintf("uses third-party action %s by %s", name, what),
		"Pin it to a full commit SHA (uses: "+name+"@<40-character sha> # "+version+"); a tag or branch can be moved to malicious code, as happened to tj-actions/changed-files in 2025.")
}

var versionTag = regexp.MustCompile(`^v?\d+(\.\d+)*([.-].*)?$`)

// actionName returns owner/repo of an action reference.
func actionName(ref string) string {
	name, _, _ := strings.Cut(ref, "@")
	parts := strings.SplitN(name, "/", 3)
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return name
}

func checkPermissions(perms *yaml.Node, where string, privileged bool, add addFunc) {
	if perms == nil {
		return
	}
	if perms.Kind == yaml.ScalarNode && perms.Value == "write-all" {
		severity := "MEDIUM"
		if privileged {
			severity = "HIGH"
		}
		add("gha-write-all", severity, perms.Line, where+" gives GITHUB_TOKEN write access to everything (permissions: write-all)",
			"List only the scopes it needs, for example permissions: {contents: read, pull-requests: write}.")
	}
}

func checkEnv(env *yaml.Node, add addFunc) {
	if env == nil || env.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(env.Content); i += 2 {
		k, v := env.Content[i], env.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			continue
		}
		if k.Value == "ACTIONS_ALLOW_UNSECURE_COMMANDS" && strings.EqualFold(v.Value, "true") {
			add("gha-unsecure-commands", "HIGH", v.Line, "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables set-env and add-path, which let any printed log line change the job's environment",
				"Remove it and write to $GITHUB_ENV and $GITHUB_PATH instead.")
		}
		if secret.Literal(k.Value, v.Value) {
			add("gha-hardcoded-secret", "HIGH", v.Line, fmt.Sprintf("env %s holds a literal secret", k.Value),
				"Store the value as an Actions secret and use ${{ secrets.NAME }}, then rotate it.")
		}
	}
}

// triggers lists the events in an on: value (a name, a list or a map).
func triggers(on *yaml.Node) []string {
	if on == nil {
		return nil
	}
	var out []string
	switch on.Kind {
	case yaml.ScalarNode:
		out = append(out, on.Value)
	case yaml.SequenceNode:
		for _, n := range on.Content {
			out = append(out, n.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(on.Content); i += 2 {
			out = append(out, on.Content[i].Value)
		}
	}
	return out
}

// key returns the key node of k in a mapping, or nil.
func key(m *yaml.Node, k string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i]
		}
	}
	return nil
}

// get returns the value of k in a mapping, or nil.
func get(m *yaml.Node, k string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
