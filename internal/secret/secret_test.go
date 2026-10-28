package secret

import "testing"

func TestLiteral(t *testing.T) {
	for _, c := range []struct {
		key, value string
		want       bool
	}{
		{"GITHUB_TOKEN", "ghp_0123456789abcdefghijklmnopqrstuvwxyz", true},
		{"ANY", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz", true},
		{"API_KEY", "a8f3k2m9q7w1z5x0", true},
		{"SESSION_SECRET", "9f2c4e7a1b3d5f8e0a6c", true},
		{"API_KEY", "${API_KEY}", false},
		{"API_KEY", "${env:API_KEY}", false},
		{"API_KEY", "<your-api-key>", false},
		{"API_KEY", "YOUR_API_KEY_HERE", false},
		{"GOOGLE_API_KEY", "GOOGLE_API_KEY_VAL", false},
		{"ALLOYDB_SECRET_NAME", "alloydb-secret-prod", false},
		{"TOKEN_FILE", "token-file-location", false},
		{"Authorization", "Bearer ${input:token}", false},
		{"GOOGLE_APPLICATION_CREDENTIALS", "/home/me/creds.json", false},
		{"LOG_LEVEL", "a8f3k2m9q7w1z5x0", false},
		{"AUTH_ENABLED", "true", false},
	} {
		if got := Literal(c.key, c.value); got != c.want {
			t.Errorf("Literal(%q, %q) = %v, want %v", c.key, c.value, got, c.want)
		}
	}
}
