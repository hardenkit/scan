package kube

import (
	"fmt"
	"strings"
)

type rule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

type binding struct {
	RoleRef struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"subjects"`
}

const leastPrivilegeFix = "List only the resources and verbs the workload needs."

func checkRole(rules []rule, add func(rule, severity, title, fix string)) {
	for i, r := range rules {
		n := fmt.Sprintf("rule %d", i+1)
		allVerbs, allResources := has(r.Verbs, "*"), has(r.Resources, "*")
		switch {
		case allVerbs && allResources:
			add("k8s-rbac-wildcard", "HIGH", n+" grants every verb on every resource (cluster-admin equivalent)", leastPrivilegeFix)
			continue // the checks below are implied
		case allVerbs || allResources:
			add("k8s-rbac-wildcard", "MEDIUM", n+" uses a wildcard ("+wildcardPart(allVerbs)+")", leastPrivilegeFix)
		}
		if esc := intersect(r.Verbs, "escalate", "bind", "impersonate"); len(esc) > 0 {
			add("k8s-rbac-escalation", "HIGH", fmt.Sprintf("%s grants %s, which lets the holder give itself more permissions", n, strings.Join(esc, ", ")),
				"Remove these verbs unless this role manages RBAC by design.")
		}
		if has(r.Resources, "secrets") || allResources {
			if read := intersect(r.Verbs, "get", "list", "watch", "*"); len(read) > 0 {
				add("k8s-rbac-secrets", "MEDIUM", fmt.Sprintf("%s can read Secrets (%s)", n, strings.Join(read, ", ")),
					"Limit Secret access to named secrets with resourceNames, or mount the secrets the workload needs instead.")
			}
		}
		if has(r.Resources, "pods/exec") || has(r.Resources, "pods/attach") {
			if len(intersect(r.Verbs, "create", "get", "*")) > 0 {
				add("k8s-rbac-exec", "MEDIUM", n+" can run commands in pods (pods/exec)", "Remove pods/exec unless this role is for interactive debugging.")
			}
		}
	}
}

func checkBinding(b binding, add func(rule, severity, title, fix string)) {
	for _, s := range b.Subjects {
		switch s.Name {
		case "system:anonymous", "system:unauthenticated":
			add("k8s-rbac-anonymous", "CRITICAL", fmt.Sprintf("binds %s %q to unauthenticated users", b.RoleRef.Kind, b.RoleRef.Name),
				"Remove this subject; anyone who can reach the API server gets these permissions.")
		case "system:authenticated":
			add("k8s-rbac-anonymous", "HIGH", fmt.Sprintf("binds %s %q to every authenticated user", b.RoleRef.Kind, b.RoleRef.Name),
				"Bind the role to specific users, groups or service accounts.")
		}
	}
	if b.RoleRef.Name == "cluster-admin" {
		add("k8s-cluster-admin", "HIGH", "grants cluster-admin", "Bind a role with only the permissions this subject needs.")
	}
}

func wildcardPart(allVerbs bool) string {
	if allVerbs {
		return "all verbs"
	}
	return "all resources"
}

func has(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func intersect(s []string, want ...string) []string {
	var out []string
	for _, w := range want {
		if has(s, w) {
			out = append(out, w)
		}
	}
	return out
}
