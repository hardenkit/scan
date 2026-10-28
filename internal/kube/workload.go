package kube

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/hardenkit/scan/internal/secret"
)

type podSpec struct {
	HostNetwork     bool         `yaml:"hostNetwork"`
	HostPID         bool         `yaml:"hostPID"`
	HostIPC         bool         `yaml:"hostIPC"`
	SecurityContext *podSecurity `yaml:"securityContext"`
	Containers      []container  `yaml:"containers"`
	InitContainers  []container  `yaml:"initContainers"`
	Volumes         []struct {
		Name     string `yaml:"name"`
		HostPath *struct {
			Path string `yaml:"path"`
		} `yaml:"hostPath"`
	} `yaml:"volumes"`
}

type podSecurity struct {
	RunAsNonRoot   *bool    `yaml:"runAsNonRoot"`
	RunAsUser      *int64   `yaml:"runAsUser"`
	SeccompProfile *seccomp `yaml:"seccompProfile"`
}

type seccomp struct {
	Type string `yaml:"type"`
}

type container struct {
	Name            string             `yaml:"name"`
	Image           string             `yaml:"image"`
	SecurityContext *containerSecurity `yaml:"securityContext"`
	Ports           []struct {
		HostPort int `yaml:"hostPort"`
	} `yaml:"ports"`
	Env []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
	Resources struct {
		Limits map[string]any `yaml:"limits"`
	} `yaml:"resources"`
}

type containerSecurity struct {
	Privileged               *bool    `yaml:"privileged"`
	AllowPrivilegeEscalation *bool    `yaml:"allowPrivilegeEscalation"`
	RunAsNonRoot             *bool    `yaml:"runAsNonRoot"`
	RunAsUser                *int64   `yaml:"runAsUser"`
	ReadOnlyRootFilesystem   *bool    `yaml:"readOnlyRootFilesystem"`
	ProcMount                string   `yaml:"procMount"`
	SeccompProfile           *seccomp `yaml:"seccompProfile"`
	Capabilities             *struct {
		Add  []string `yaml:"add"`
		Drop []string `yaml:"drop"`
	} `yaml:"capabilities"`
}

// podSpecOf returns the pod template of a workload object, or nil.
func podSpecOf(node *yaml.Node, kind string) *podSpec {
	switch kind {
	case "Pod":
		var o struct {
			Spec podSpec `yaml:"spec"`
		}
		if node.Decode(&o) == nil {
			return &o.Spec
		}
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
		var o struct {
			Spec struct {
				Template struct {
					Spec podSpec `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if node.Decode(&o) == nil {
			return &o.Spec.Template.Spec
		}
	case "CronJob":
		var o struct {
			Spec struct {
				JobTemplate struct {
					Spec struct {
						Template struct {
							Spec podSpec `yaml:"spec"`
						} `yaml:"template"`
					} `yaml:"spec"`
				} `yaml:"jobTemplate"`
			} `yaml:"spec"`
		}
		if node.Decode(&o) == nil {
			return &o.Spec.JobTemplate.Spec.Template.Spec
		}
	}
	return nil
}

// Capabilities the Pod Security "baseline" profile allows adding.
var baselineCaps = map[string]bool{
	"AUDIT_WRITE": true, "CHOWN": true, "DAC_OVERRIDE": true, "FOWNER": true, "FSETID": true,
	"KILL": true, "MKNOD": true, "NET_BIND_SERVICE": true, "SETFCAP": true, "SETGID": true,
	"SETPCAP": true, "SETUID": true, "SYS_CHROOT": true,
}

// Host paths that hand over the node: the root filesystem or a container runtime socket.
func nodeTakeover(p string) bool {
	p = strings.TrimSuffix(p, "/")
	return p == "" || strings.HasSuffix(p, ".sock") || p == "/var/run" || p == "/run" ||
		p == "/etc" || p == "/root" || p == "/proc" || p == "/var/lib/kubelet" || p == "/var/lib/docker"
}

const restrictedFix = `Set securityContext on the container: runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, seccompProfile: {type: RuntimeDefault}.`

func checkPod(spec *podSpec, add func(rule, severity, title, fix string)) {
	for _, ns := range []struct {
		on   bool
		name string
	}{{spec.HostNetwork, "hostNetwork"}, {spec.HostPID, "hostPID"}, {spec.HostIPC, "hostIPC"}} {
		if ns.on {
			add("k8s-host-namespace", "HIGH", fmt.Sprintf("pod shares the node's namespaces (%s: true)", ns.name),
				"Remove "+ns.name+"; it lets the pod see and reach the node's processes or network.")
		}
	}
	for _, v := range spec.Volumes {
		if v.HostPath == nil {
			continue
		}
		if nodeTakeover(v.HostPath.Path) {
			add("k8s-host-path", "CRITICAL", fmt.Sprintf("volume %q mounts %s from the node", v.Name, v.HostPath.Path),
				"Remove the hostPath volume; this path gives the pod control of the node and every pod on it.")
		} else {
			add("k8s-host-path", "HIGH", fmt.Sprintf("volume %q mounts %s from the node", v.Name, v.HostPath.Path),
				"Use a persistentVolumeClaim, configMap or emptyDir instead of hostPath.")
		}
	}

	pod := spec.SecurityContext
	if pod == nil {
		pod = &podSecurity{}
	}
	all := append(append([]container{}, spec.InitContainers...), spec.Containers...)
	for _, c := range all {
		name := fmt.Sprintf("container %q", c.Name)
		sc := c.SecurityContext
		if sc == nil {
			sc = &containerSecurity{}
		}

		if isTrue(sc.Privileged) {
			add("k8s-privileged", "CRITICAL", name+" is privileged",
				"Remove privileged: true; a privileged container has full access to the node. Add only the specific capabilities it needs.")
		}
		var badCaps []string
		if sc.Capabilities != nil {
			for _, cp := range sc.Capabilities.Add {
				cp = strings.TrimPrefix(strings.ToUpper(cp), "CAP_")
				if !baselineCaps[cp] {
					badCaps = append(badCaps, cp)
				}
			}
		}
		if len(badCaps) > 0 {
			add("k8s-dangerous-capabilities", "HIGH", fmt.Sprintf("%s adds capabilities %s", name, strings.Join(badCaps, ", ")),
				"Remove these capabilities; they allow escaping the container or changing the node.")
		}
		if sc.ProcMount == "Unmasked" {
			add("k8s-unmasked-proc", "HIGH", name+" mounts /proc unmasked", "Remove procMount: Unmasked.")
		}
		profile := sc.SeccompProfile
		if profile == nil {
			profile = pod.SeccompProfile
		}
		if profile != nil && profile.Type == "Unconfined" {
			add("k8s-seccomp-unconfined", "HIGH", name+" runs without a seccomp filter (Unconfined)",
				"Use seccompProfile: {type: RuntimeDefault}.")
		}
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				add("k8s-host-port", "MEDIUM", fmt.Sprintf("%s binds host port %d", name, p.HostPort),
					"Expose the port through a Service instead of hostPort.")
				break
			}
		}
		for _, e := range c.Env {
			if secret.Literal(e.Name, e.Value) {
				add("k8s-hardcoded-secret", "HIGH", fmt.Sprintf("%s has a literal secret in env %s", name, e.Name),
					"Move the value to a Secret and reference it with valueFrom.secretKeyRef, then rotate it.")
			}
		}
		if tag := imageTag(c.Image); c.Image != "" && (tag == "" || tag == "latest") {
			add("k8s-image-unpinned", "MEDIUM", fmt.Sprintf("%s runs image %s without a pinned version", name, c.Image),
				"Pin a version tag, or better a digest (image@sha256:...), so every node runs the image you tested.")
		}

		// Pod Security "restricted" profile, reported once per container:
		// medium if it can run as root or escalate, low for the rest.
		var gaps []string
		severity := "LOW"
		runAsUser := sc.RunAsUser
		if runAsUser == nil {
			runAsUser = pod.RunAsUser
		}
		switch {
		case runAsUser != nil && *runAsUser == 0:
			gaps, severity = append(gaps, "runs as root (runAsUser: 0)"), "MEDIUM"
		case !isTrue(sc.RunAsNonRoot) && !isTrue(pod.RunAsNonRoot) && runAsUser == nil:
			gaps, severity = append(gaps, "may run as root (no runAsNonRoot)"), "MEDIUM"
		}
		if !isFalse(sc.AllowPrivilegeEscalation) && !isTrue(sc.Privileged) {
			gaps, severity = append(gaps, "allows privilege escalation"), "MEDIUM"
		}
		if sc.Capabilities == nil || !containsFold(sc.Capabilities.Drop, "ALL") {
			gaps = append(gaps, "keeps default capabilities")
		}
		if profile == nil || (profile.Type != "RuntimeDefault" && profile.Type != "Localhost" && profile.Type != "Unconfined") {
			gaps = append(gaps, "no seccomp profile")
		}
		if len(gaps) > 0 {
			add("k8s-restricted", severity, fmt.Sprintf("%s doesn't meet the restricted Pod Security Standard: %s", name, strings.Join(gaps, ", ")), restrictedFix)
		}

		var weak []string
		if !isTrue(sc.ReadOnlyRootFilesystem) {
			weak = append(weak, "writable root filesystem")
		}
		if _, ok := c.Resources.Limits["memory"]; !ok {
			weak = append(weak, "no memory limit")
		}
		if len(weak) > 0 {
			add("k8s-hardening", "LOW", fmt.Sprintf("%s: %s", name, strings.Join(weak, ", ")),
				"Set readOnlyRootFilesystem: true (mount an emptyDir for paths it writes to) and resources.limits.memory.")
		}
	}
}

// imageTag returns the tag of an image reference, or "" if it has none.
// Images pinned by digest return "digest".
func imageTag(image string) string {
	if strings.Contains(image, "@sha256:") {
		return "digest"
	}
	name := image
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.Index(name, ":"); i >= 0 {
		return name[i+1:]
	}
	return ""
}

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }

func containsFold(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
