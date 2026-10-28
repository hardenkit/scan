// Package secret tells literal secrets in config files apart from
// environment references and placeholders.
package secret

import (
	"regexp"
	"strings"
)

var (
	// Token formats with a recognizable prefix.
	token = regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{30,}|glpat-[\w-]{20,}|xox[abpr]-[\w-]{10,}|AKIA[0-9A-Z]{16}|hf_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{20,}|npm_[A-Za-z0-9]{36})\b`)
	// Setting names that usually hold a secret.
	name = regexp.MustCompile(`(?i)(key|token|secret|passw|pwd|auth|credential|cookie|bearer)`)
	// Names that refer to a secret rather than hold it (DB_SECRET_NAME, KEY_FILE).
	reference = regexp.MustCompile(`(?i)[_.-]?(name|id|file|path|dir|url|uri|arn|ref|region|endpoint|version|type|mode|enabled|length|ttl)$`)
	// Placeholders in the style of an environment variable name (API_KEY_VALUE).
	placeholder = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`)
)

// HasToken reports whether s contains a token in a well-known format.
func HasToken(s string) bool { return token.MatchString(s) }

// Literal reports whether the value of a setting named key looks like a real
// secret rather than an environment reference or a placeholder.
func Literal(key, value string) bool {
	if token.MatchString(value) {
		return true
	}
	if !name.MatchString(key) || reference.MatchString(key) {
		return false
	}
	v := strings.TrimSpace(value)
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "Basic "))
	if len(v) < 12 || strings.Contains(v, " ") {
		return false
	}
	lower := strings.ToLower(v)
	switch {
	case strings.Contains(v, "${"), strings.HasPrefix(v, "$"), strings.Contains(v, "{{"), strings.HasPrefix(v, "%"),
		strings.ContainsAny(v, "<>"), strings.Contains(lower, "your"), strings.Contains(lower, "xxxx"),
		strings.Contains(lower, "changeme"), strings.Contains(lower, "example"), strings.Contains(lower, "placeholder"),
		IsPath(v), strings.HasSuffix(lower, ".json"), strings.Contains(v, "://"), placeholder.MatchString(v):
		return false
	}
	return true
}

// IsPath reports whether s looks like a file path rather than a value.
func IsPath(s string) bool {
	return strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.Contains(s, `\`)
}
