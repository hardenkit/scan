package kube

import (
	"context"
	"os"
	"os/exec"
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

// A deployment that meets the restricted profile; it must produce no issues.
const hardened = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          env:
            - name: DATABASE_PASSWORD
              valueFrom:
                secretKeyRef: {name: db, key: password}
            - name: LOG_LEVEL
              value: info
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            limits:
              memory: 256Mi
`

const risky = `# A DaemonSet that owns the node.
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent
  namespace: monitoring
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      volumes:
        - name: docker
          hostPath:
            path: /var/run/docker.sock
        - name: logs
          hostPath:
            path: /var/log
      containers:
        - name: agent
          image: acme/agent
          securityContext:
            privileged: true
            capabilities:
              add: [SYS_ADMIN, NET_BIND_SERVICE]
          ports:
            - containerPort: 9100
              hostPort: 9100
          env:
            - name: API_TOKEN
              value: a8f3k2m9q7w1z5x0b4
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: acme/backup:latest
              securityContext:
                runAsUser: 0
`

const rbac = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: operator
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind", "escalate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: open
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects:
  - {kind: Group, name: system:unauthenticated, apiGroup: rbac.authorization.k8s.io}
---
apiVersion: v1
kind: Secret
metadata:
  name: db
stringData:
  password: hunter2hunter2
---
apiVersion: v1
kind: Secret
metadata:
  name: empty
data: {}
`

func rulesByObject(r *Report) map[string][]string {
	out := map[string][]string{}
	for _, is := range r.Issues {
		obj, _, _ := strings.Cut(is.Title, ":")
		out[obj] = append(out[obj], is.Rule)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "k8s/api.yaml", hardened)
	writeFile(t, dir, "k8s/agent.yml", risky)
	writeFile(t, dir, "k8s/rbac.yaml", rbac)
	// Not Kubernetes: ignored.
	writeFile(t, dir, ".github/workflows/ci.yml", "name: CI\non: push\njobs: {}\n")
	writeFile(t, dir, "docker-compose.yaml", "services:\n  web:\n    image: nginx\n    privileged: true\n")
	writeFile(t, dir, "node_modules/x/pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {hostPID: true}\n")

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"DaemonSet/agent": {
			"k8s-dangerous-capabilities", "k8s-hardcoded-secret", "k8s-hardening", "k8s-host-namespace", "k8s-host-namespace",
			"k8s-host-path", "k8s-host-path", "k8s-host-port", "k8s-image-unpinned", "k8s-privileged", "k8s-restricted",
		},
		"CronJob/backup":          {"k8s-hardening", "k8s-image-unpinned", "k8s-restricted"},
		"ClusterRole/operator":    {"k8s-rbac-escalation", "k8s-rbac-secrets", "k8s-rbac-wildcard"},
		"ClusterRoleBinding/open": {"k8s-cluster-admin", "k8s-rbac-anonymous"},
		"Secret/db":               {"k8s-secret-in-repo"},
	}
	if got := rulesByObject(r); !reflect.DeepEqual(got, want) {
		for _, is := range r.Issues {
			t.Logf("%s %s:%d %s", is.Severity, is.File, is.Line, is.Title)
		}
		t.Errorf("got %v\nwant %v", got, want)
	}
	if len(r.Resources) != 7 {
		t.Errorf("got %d resources, want 7: %+v", len(r.Resources), r.Resources)
	}
	if want := []string{"acme/agent", "acme/backup:latest", "ghcr.io/acme/api:1.4.2"}; !reflect.DeepEqual(r.Images, want) {
		t.Errorf("images = %v, want %v", r.Images, want)
	}
	if first := r.Issues[0]; first.Severity != "CRITICAL" {
		t.Errorf("first issue %+v, want CRITICAL", first)
	}
	for _, is := range r.Issues {
		if is.Line == 0 {
			t.Errorf("issue without a line: %+v", is)
		}
		if strings.Contains(is.Title, "a8f3k2m9") || strings.Contains(is.Title, "hunter2") {
			t.Errorf("issue leaks a secret: %+v", is)
		}
	}
	for _, is := range r.Issues {
		if strings.Contains(is.Title, "privileged") && !strings.HasPrefix(is.File, "k8s/agent.yml") {
			t.Errorf("privileged reported outside the DaemonSet: %+v", is)
		}
	}
}

func TestScanRestrictedDetails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pod.yaml", `apiVersion: v1
kind: Pod
metadata: {name: web}
spec:
  containers:
    - name: web
      image: nginx:1.27
`)
	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var restricted string
	for _, is := range r.Issues {
		if is.Rule == "k8s-restricted" {
			restricted = is.Title
		}
	}
	for _, gap := range []string{"may run as root", "allows privilege escalation", "keeps default capabilities", "no seccomp profile"} {
		if !strings.Contains(restricted, gap) {
			t.Errorf("restricted issue %q is missing %q", restricted, gap)
		}
	}
}

func TestScanNoKubernetes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", "port: 8080\n")
	r, err := Scan(context.Background(), dir)
	if err != nil || r != nil {
		t.Errorf("got %+v, %v; want nil report", r, err)
	}
}

const chartYAML = "apiVersion: v2\nname: web\nversion: 0.1.0\n"

const chartTemplate = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-web
spec:
  template:
    spec:
      containers:
        - name: web
          image: "{{ .Values.image }}"
          securityContext:
            privileged: {{ .Values.privileged }}
`

func TestScanHelmChart(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "charts/web/Chart.yaml", chartYAML)
	writeFile(t, dir, "charts/web/values.yaml", "image: acme/web:2.0.0\nprivileged: true\n")
	writeFile(t, dir, "charts/web/templates/deployment.yaml", chartTemplate)

	if _, err := exec.LookPath("helm"); err != nil {
		r, err := Scan(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		if r == nil || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "install helm") || len(r.Issues) != 0 {
			t.Errorf("without helm: got %+v, want one warning and no issues", r)
		}
		t.Skip("helm not installed; rendering not tested")
	}

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Charts, []string{"charts/web"}) {
		t.Errorf("charts = %v, warnings = %v", r.Charts, r.Warnings)
	}
	found := false
	for _, is := range r.Issues {
		if is.Rule == "k8s-privileged" {
			found = true
			if is.File != "charts/web/templates/deployment.yaml" || !strings.Contains(is.Title, "Deployment/hardenkit-scan-web") {
				t.Errorf("privileged issue = %+v", is)
			}
		}
	}
	if !found {
		t.Errorf("no privileged issue from the rendered chart: %+v", r.Issues)
	}
}
