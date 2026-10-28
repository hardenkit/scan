package aistack

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/hardenkit/scan/internal/issue"
)

// sourceRules are risky settings in Python code that loads models or data.
var sourceRules = []struct {
	rule, severity, title, fix string
	pattern                    *regexp.Regexp
}{
	{
		rule:     "code-trust-remote-code",
		severity: "MEDIUM",
		title:    "trust_remote_code=True downloads and runs Python code from the model repository",
		fix:      "Remove trust_remote_code, or pin the model with revision=\"<commit sha>\" after reviewing its code.",
		pattern:  regexp.MustCompile(`\btrust_remote_code\s*=\s*True\b`),
	},
	{
		rule:     "code-dangerous-deserialization",
		severity: "HIGH",
		title:    "allow_dangerous_deserialization=True loads a pickle that can run code",
		fix:      "Only load vector stores you created yourself, from storage no one else can write to; otherwise rebuild the index from the source documents.",
		pattern:  regexp.MustCompile(`\ballow_dangerous_deserialization\s*=\s*True\b`),
	},
	{
		rule:     "code-unsafe-torch-load",
		severity: "MEDIUM",
		title:    "torch.load(weights_only=False) can run code from the loaded file",
		fix:      "Use weights_only=True (the default since PyTorch 2.6), or store the weights as safetensors.",
		pattern:  regexp.MustCompile(`\btorch\.load\(.*\bweights_only\s*=\s*False\b`),
	},
}

const maxSourceSize = 2 << 20

func checkSource(r *Report, file, rel string) {
	info, err := os.Stat(file)
	if err != nil || info.Size() > maxSourceSize {
		return
	}
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), maxSourceSize)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if !strings.Contains(text, "=") {
			continue
		}
		code, _, _ := strings.Cut(text, "#")
		for _, rule := range sourceRules {
			if rule.pattern.MatchString(code) {
				r.Issues = append(r.Issues, issue.Issue{Rule: rule.rule, Severity: rule.severity, File: rel, Line: line, Title: rule.title, Fix: rule.fix})
			}
		}
	}
}
