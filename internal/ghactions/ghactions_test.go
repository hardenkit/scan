package ghactions

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, data string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A workflow that follows the guidance; it must produce no issues.
const safe = `name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: golangci/golangci-lint-action@4afd733a84b1f43292c63897423277bb7f4313a9 # v8
      - name: Greet
        env:
          TITLE: ${{ github.event.pull_request.title }}
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: |
          echo "PR: $TITLE"
          echo "sha ${{ github.sha }} by ${{ github.actor }}"
      - uses: ./.github/actions/setup
        with:
          key: deps-v2-node20-linux
      - uses: docker://alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
`

const target = `name: Label
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v45
      - run: |
          npm ci
          echo "Title: ${{ github.event.pull_request.title }}"
          echo "again ${{ github.event.pull_request.title }}"
`

const comments = `on:
  issue_comment:
    types: [created]
jobs:
  reply:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const body = "${{ github.event.comment.body }}"
      - uses: peter-evans/create-or-update-comment@main
        with:
          api-key: a8f3k2m9q7w1z5x0b4c6
      - run: curl -fsSL https://example.com/install.sh | sudo bash
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
`

const push = `on: push
jobs:
  release:
    uses: acme/workflows/.github/workflows/release.yml@main
    secrets: inherit
  local:
    uses: ./.github/workflows/build.yml
    secrets: inherit
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.head_ref }}"
      - uses: docker://ghcr.io/acme/tool:1.2
      - uses: docker://ghcr.io/acme/tool:1.2
`

const composite = `name: Setup
runs:
  using: composite
  steps:
    - uses: some/action@v1.2.3
    - run: echo "${{ github.event.head_commit.message }}"
      shell: bash
`

func rulesByFile(r *Report) map[string][]string {
	out := map[string][]string{}
	for _, is := range r.Issues {
		out[is.File] = append(out[is.File], is.Severity+" "+is.Rule)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".github/workflows/ci.yml", safe)
	writeFile(t, dir, ".github/workflows/label.yaml", target)
	writeFile(t, dir, ".github/workflows/comments.yml", comments)
	writeFile(t, dir, ".github/workflows/push.yml", push)
	writeFile(t, dir, ".github/actions/setup/action.yml", composite)
	// Not workflows: ignored.
	writeFile(t, dir, "k8s/deploy.yaml", "run: echo ${{ github.event.issue.title }}\n")
	writeFile(t, dir, ".github/dependabot.yml", "version: 2\n")
	writeFile(t, dir, "node_modules/x/.github/workflows/ci.yml", target)
	writeFile(t, dir, "docker/action.yml", "name: x\nruns:\n  using: docker\n  image: Dockerfile\n")

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		".github/workflows/label.yaml": {
			"CRITICAL gha-script-injection", "CRITICAL gha-untrusted-checkout", "HIGH gha-write-all", "MEDIUM gha-unpinned-action",
		},
		".github/workflows/comments.yml": {
			"CRITICAL gha-script-injection", "HIGH gha-hardcoded-secret", "HIGH gha-unsecure-commands",
			"LOW gha-remote-script", "MEDIUM gha-unpinned-action",
		},
		".github/workflows/push.yml": {
			"HIGH gha-script-injection", "LOW gha-default-permissions", "MEDIUM gha-secrets-inherit",
			"MEDIUM gha-unpinned-action", "MEDIUM gha-unpinned-action",
		},
		".github/actions/setup/action.yml": {"HIGH gha-script-injection", "MEDIUM gha-unpinned-action"},
	}
	if got := rulesByFile(r); !reflect.DeepEqual(got, want) {
		for _, is := range r.Issues {
			t.Logf("%s %s:%d %s", is.Severity, is.File, is.Line, is.Title)
		}
		t.Errorf("got %v\nwant %v", got, want)
	}
	if len(r.Workflows) != 5 {
		t.Errorf("got %d workflows, want 5: %+v", len(r.Workflows), r.Workflows)
	}
	for _, is := range r.Issues {
		if is.Line == 0 {
			t.Errorf("issue without a line: %+v", is)
		}
		if strings.Contains(is.Title, "a8f3k2m9") {
			t.Errorf("issue leaks a secret: %+v", is)
		}
	}
	lines := map[string]int{}
	for _, is := range r.Issues {
		lines[is.File+" "+is.Rule] = is.Line
	}
	for k, line := range map[string]int{
		".github/workflows/label.yaml gha-script-injection":   14, // inside the run block
		".github/workflows/label.yaml gha-untrusted-checkout": 10, // the checkout ref
		".github/workflows/comments.yml gha-script-injection": 13,
		".github/workflows/push.yml gha-default-permissions":  1,
	} {
		if lines[k] != line {
			t.Errorf("%s at line %d, want %d", k, lines[k], line)
		}
	}
	wantActions := []string{
		"acme/workflows/.github/workflows/release.yml@main", "actions/checkout@v4", "actions/github-script@v7",
		"docker://alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1", "docker://ghcr.io/acme/tool:1.2",
		"golangci/golangci-lint-action@4afd733a84b1f43292c63897423277bb7f4313a9", "peter-evans/create-or-update-comment@main",
		"some/action@v1.2.3", "tj-actions/changed-files@v45",
	}
	if !reflect.DeepEqual(r.Actions, wantActions) {
		t.Errorf("actions = %v", r.Actions)
	}
}

const gatedComment = `on: issue_comment
permissions:
  contents: read
jobs:
  check:
    if: contains(fromJSON('["MEMBER", "OWNER"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
  test:
    needs: [check]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/merge
      - run: make test
`

func TestGatedCheckout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".github/workflows/x.yml", gatedComment)
	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Issues) != 1 {
		t.Fatalf("got %+v, want one issue", r.Issues)
	}
	is := r.Issues[0]
	if is.Rule != "gha-untrusted-checkout" || is.Severity != "HIGH" || strings.Contains(is.Title, "write token") || !strings.Contains(is.Title, "if: check") {
		t.Errorf("got %+v", is)
	}
}

func TestBranchAndTag(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".github/workflows/x.yml", push)
	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, is := range r.Issues {
		if is.Rule == "gha-unpinned-action" {
			titles = append(titles, is.Title)
		}
	}
	sort.Strings(titles)
	want := []string{
		"uses container ghcr.io/acme/tool:1.2 without a digest",
		"uses third-party action acme/workflows/.github/workflows/release.yml by branch main",
	}
	if !reflect.DeepEqual(titles, want) {
		t.Errorf("got %q", titles)
	}
}

func TestScanGitHubDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".github/workflows/x.yml", push)
	r, err := Scan(context.Background(), filepath.Join(dir, ".github"))
	if err != nil || r == nil || len(r.Workflows) != 1 || r.Workflows[0].File != "workflows/x.yml" {
		t.Errorf("got %+v, %v; want workflows/x.yml", r, err)
	}
}

func TestScanNoWorkflows(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", "port: 8080\n")
	r, err := Scan(context.Background(), dir)
	if err != nil || r != nil {
		t.Errorf("got %+v, %v; want nil report", r, err)
	}
}
