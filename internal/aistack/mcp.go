package aistack

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// isMCPConfig reports whether rel is a file MCP clients read servers from:
// Claude Code (.mcp.json), Claude Desktop, Cursor (.cursor/mcp.json),
// VS Code (.vscode/mcp.json), Windsurf (mcp_config.json), Gemini CLI.
func isMCPConfig(rel string) bool {
	switch path.Base(rel) {
	case ".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json":
		return true
	case "settings.json":
		return path.Base(path.Dir(rel)) == ".gemini"
	}
	return false
}

type mcpConfig struct {
	MCPServers map[string]mcpEntry `json:"mcpServers"`
	Servers    map[string]mcpEntry `json:"servers"` // VS Code
}

type mcpEntry struct {
	Command   string         `json:"command"`
	Args      []any          `json:"args"`
	Env       map[string]any `json:"env"`
	Headers   map[string]any `json:"headers"`
	URL       string         `json:"url"`
	ServerURL string         `json:"serverUrl"` // Windsurf
	HTTPURL   string         `json:"httpUrl"`   // Gemini CLI
}

const maxConfigSize = 1 << 20

func checkMCP(r *Report, file, rel string) {
	info, err := os.Stat(file)
	if err != nil || info.Size() > maxConfigSize {
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}
	var cfg mcpConfig
	if err := json.Unmarshal(stripJSONC(data), &cfg); err != nil {
		return // not an MCP config after all, or one the client can't read either
	}
	servers := cfg.MCPServers
	if servers == nil {
		servers = cfg.Servers
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		e := servers[name]
		u := firstNonEmpty(e.URL, e.ServerURL, e.HTTPURL)
		args := make([]string, 0, len(e.Args))
		for _, a := range e.Args {
			args = append(args, fmt.Sprint(a))
		}
		r.MCPServers = append(r.MCPServers, MCPServer{Name: name, File: rel, Command: strings.TrimSpace(e.Command + " " + strings.Join(args, " ")), URL: u})

		add := func(rule, severity, title, fix string) {
			r.Issues = append(r.Issues, Issue{Rule: rule, Severity: severity, File: rel, Title: fmt.Sprintf("MCP server %q: %s", name, title), Fix: fix})
		}
		const secretFix = "Move the secret to an environment variable and reference it (for example \"${GITHUB_TOKEN}\"), then rotate it: anyone with this file has it."
		for _, k := range sortedKeys(e.Env) {
			if isLiteralSecret(k, fmt.Sprint(e.Env[k])) {
				add("mcp-hardcoded-secret", "HIGH", fmt.Sprintf("env %s holds a literal secret", k), secretFix)
			}
		}
		for _, k := range sortedKeys(e.Headers) {
			if isLiteralSecret(k, fmt.Sprint(e.Headers[k])) {
				add("mcp-hardcoded-secret", "HIGH", fmt.Sprintf("header %s holds a literal secret", k), secretFix)
			}
		}
		for i := range args {
			if argHasSecret(args, i) {
				add("mcp-hardcoded-secret", "HIGH", fmt.Sprintf("argument %d holds a literal secret", i+1), secretFix)
			}
		}
		if u != "" {
			checkMCPURL(u, add, secretFix)
		}
		if e.Command != "" {
			checkMCPCommand(e.Command, args, add)
		}
	}
}

func checkMCPURL(raw string, add func(rule, severity, title, fix string), secretFix string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	if u.Scheme == "http" && !isLocalHost(u.Hostname()) {
		add("mcp-insecure-transport", "HIGH", "remote server over plain HTTP",
			"Use an https:// URL; over HTTP, tool calls, results and tokens can be read and changed in transit.")
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			if isLiteralSecret(k, v) {
				add("mcp-hardcoded-secret", "HIGH", fmt.Sprintf("URL parameter %s holds a literal secret", k), secretFix)
			}
		}
	}
}

func isLocalHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".localhost")
}

func checkMCPCommand(command string, args []string, add func(rule, severity, title, fix string)) {
	bin := strings.ToLower(path.Base(strings.ReplaceAll(command, `\`, "/")))
	bin = strings.TrimSuffix(bin, ".exe")
	bin = strings.TrimSuffix(bin, ".cmd")

	const pinFix = "Pin an exact version so a compromised or changed release can't run on the next start (for example \"pkg@1.4.2\")."
	switch bin {
	case "npx", "bunx":
		checkPin(npmPinned, packageArg(args, "-p", "--package"), add, pinFix)
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			checkPin(npmPinned, packageArg(args[1:], "-p", "--package"), add, pinFix)
		}
	case "uvx":
		if from := flagValue(args, "--from"); from != "" {
			checkPin(pyPinned, from, add, pinFix)
		} else {
			checkPin(pyPinned, packageArg(args, "--with", "--python", "--index-url"), add, pinFix)
		}
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			if spec := flagValue(args, "--spec"); spec != "" {
				checkPin(pyPinned, spec, add, pinFix)
			} else {
				checkPin(pyPinned, packageArg(args[1:], "--python", "--index-url"), add, pinFix)
			}
		}
	case "docker", "podman":
		if len(args) > 0 && args[0] == "run" {
			checkContainer(args[1:], add)
		}
	case "sh", "bash", "zsh", "cmd", "powershell", "pwsh":
		joined := strings.ToLower(strings.Join(args, " "))
		fetch := strings.Contains(joined, "curl ") || strings.Contains(joined, "wget ") || strings.Contains(joined, "invoke-webrequest") || strings.Contains(joined, "iwr ")
		pipe := pipeToShell.MatchString(joined)
		if fetch && pipe {
			add("mcp-remote-script", "HIGH", "downloads and runs a script on every start",
				"Install the server once from a pinned, verified release and run the installed binary instead.")
		}
	}
}

func checkPin(pinned func(string) bool, pkg string, add func(rule, severity, title, fix string), fix string) {
	if pkg == "" || isLocalPath(pkg) || strings.Contains(pkg, "://") || pinned(pkg) {
		return
	}
	add("mcp-unpinned-package", "MEDIUM", fmt.Sprintf("runs %s without a pinned version", pkg), fix)
}

// npmPinned reports whether an npm spec names a version: pkg@1.2.3 or
// @scope/pkg@1.2.3, but not a moving tag like @latest.
func npmPinned(spec string) bool {
	i := strings.LastIndex(spec, "@")
	if i <= 0 {
		return false
	}
	v := spec[i+1:]
	return v != "" && v != "latest" && v != "next" && (v[0] >= '0' && v[0] <= '9' || v[0] == 'v' || v[0] == '=')
}

// pyPinned reports whether a Python spec pins a version: pkg==1.2.3 or pkg@1.2.3.
func pyPinned(spec string) bool {
	if strings.Contains(spec, "==") {
		return true
	}
	i := strings.LastIndex(spec, "@")
	return i > 0 && spec[i+1:] != "" && spec[i+1:] != "latest"
}

// Docker flags that take a separate value, so the image name isn't mistaken for one.
var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true,
	"--mount": true, "--name": true, "--network": true, "--net": true, "-p": true,
	"--publish": true, "-w": true, "--workdir": true, "-u": true, "--user": true,
	"--entrypoint": true, "--platform": true, "--cap-add": true, "--pid": true,
	"-l": true, "--label": true, "-h": true, "--hostname": true, "--add-host": true,
	"--memory": true, "-m": true, "--cpus": true, "--pull": true, "--security-opt": true,
}

func checkContainer(args []string, add func(rule, severity, title, fix string)) {
	var image string
	var risky []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			image = a
			break
		}
		flag, val, hasVal := strings.Cut(a, "=")
		if !hasVal && dockerValueFlags[flag] && i+1 < len(args) {
			i++
			val = args[i]
		}
		switch {
		case flag == "--privileged":
			risky = append(risky, "--privileged")
		case (flag == "--network" || flag == "--net" || flag == "--pid") && val == "host":
			risky = append(risky, flag+"=host")
		case flag == "--cap-add" && (strings.EqualFold(val, "ALL") || strings.EqualFold(val, "SYS_ADMIN")):
			risky = append(risky, "--cap-add="+val)
		case flag == "-v" || flag == "--volume" || flag == "--mount":
			if strings.Contains(val, "docker.sock") {
				risky = append(risky, "mounts the Docker socket")
			} else if src := mountSource(flag, val); src == "/" || src == `C:\` {
				risky = append(risky, "mounts the host root filesystem")
			}
		}
	}
	if len(risky) > 0 {
		add("mcp-unsafe-container", "HIGH", "container runs with "+strings.Join(risky, ", "),
			"Drop these options: they give the server, and anyone who can steer it through prompt injection, control of the host.")
	}
	if image == "" {
		return
	}
	if strings.Contains(image, "@sha256:") {
		return
	}
	name := image
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	tag := ""
	if i := strings.Index(name, ":"); i >= 0 {
		tag = name[i+1:]
	}
	if tag == "" || tag == "latest" {
		add("mcp-unpinned-package", "MEDIUM", fmt.Sprintf("runs image %s without a pinned version", image),
			"Pin a version tag, or better a digest (image@sha256:...), so a changed image can't run on the next start.")
	}
}

func mountSource(flag, val string) string {
	if flag == "--mount" {
		for _, part := range strings.Split(val, ",") {
			if k, v, ok := strings.Cut(part, "="); ok && (k == "source" || k == "src") {
				return v
			}
		}
		return ""
	}
	src, _, _ := strings.Cut(val, ":")
	return src
}

// packageArg returns the first positional argument, or the value of one of
// the package flags (npx -p pkg). Flags in valueFlags take a separate value.
func packageArg(args []string, valueFlags ...string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if !strings.HasPrefix(a, "-") {
			return a
		}
		if flag, val, ok := strings.Cut(a, "="); ok {
			if flag == "-p" || flag == "--package" {
				return val
			}
			continue
		}
		if contains(valueFlags, a) && i+1 < len(args) {
			if a == "-p" || a == "--package" {
				return args[i+1]
			}
			i++
		}
	}
	return ""
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v
		}
	}
	return ""
}

func isLocalPath(s string) bool {
	return strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.Contains(s, `\`)
}

var (
	// Token formats with a recognizable prefix.
	tokenPattern = regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{30,}|glpat-[\w-]{20,}|xox[abpr]-[\w-]{10,}|AKIA[0-9A-Z]{16}|hf_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{20,}|npm_[A-Za-z0-9]{36})\b`)
	secretName   = regexp.MustCompile(`(?i)(key|token|secret|passw|pwd|auth|credential|cookie|bearer)`)
	secretFlag   = regexp.MustCompile(`(?i)^--?[\w-]*(key|token|secret|password)[\w-]*$`)
	pipeToShell  = regexp.MustCompile(`\|\s*(sh|bash|zsh|python3?|iex)\b`)
)

// isLiteralSecret reports whether the value of a setting named name looks
// like a real secret rather than an environment reference or a placeholder.
func isLiteralSecret(name, value string) bool {
	if tokenPattern.MatchString(value) {
		return true
	}
	if !secretName.MatchString(name) {
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
		isLocalPath(v), strings.HasSuffix(lower, ".json"), strings.Contains(v, "://"):
		return false
	}
	return true
}

// argHasSecret checks args[i] for a token, either on its own or as the value
// of a flag such as --api-key=... or --token ....
func argHasSecret(args []string, i int) bool {
	a := args[i]
	if tokenPattern.MatchString(a) {
		return true
	}
	if flag, val, ok := strings.Cut(a, "="); ok && secretFlag.MatchString(flag) {
		return isLiteralSecret(flag, val)
	}
	if i > 0 && secretFlag.MatchString(args[i-1]) {
		return isLiteralSecret(args[i-1], a)
	}
	// mcp-remote style: --header "Authorization: Bearer ...".
	if k, v, ok := strings.Cut(a, ":"); ok && i > 0 && args[i-1] == "--header" {
		return isLiteralSecret(k, strings.TrimSpace(v))
	}
	return false
}

// stripJSONC removes // and /* */ comments and trailing commas, which VS Code
// and some other clients allow in their config files.
func stripJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(data) {
				i++
				out = append(out, data[i])
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
		case c == '}' || c == ']':
			// Drop a trailing comma before the closing bracket.
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\t' || out[j] == '\n' || out[j] == '\r') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
