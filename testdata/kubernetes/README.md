# Kubernetes test fixture

Deliberately risky manifests for testing `hardenkit scan`: a privileged
DaemonSet with the container runtime socket mounted, a cluster-wide wildcard
role, an unpinned image and a literal secret in an env var. The Helm chart in
`chart/` is hardened and should produce no issues. The secret is fake.
