package aistack

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hardenkit/scan/internal/inventory"
	"github.com/hardenkit/scan/internal/secret"
)

// Pickles of an object whose __reduce__ returns (os.system, ("echo pwned",)),
// generated with Python's pickle module at each protocol.
var evilPickles = map[string]string{
	"protocol 0": "636f730a73797374656d0a70300a28566563686f2070776e65640a70310a7470320a5270330a2e",
	"protocol 2": "8002636f730a73797374656d0a7100580a0000006563686f2070776e656471018571025271032e",
	"protocol 4": "80049522000000000000008c026f73948c0673797374656d9493948c0a6563686f2070776e656494859452942e",
	"protocol 5": "80059522000000000000008c026f73948c0673797374656d9493948c0a6563686f2070776e656494859452942e",
	// Hand-built: module and name come from the memo (BINGET) before STACK_GLOBAL.
	"memo": "80048c05706f736978948c0673797374656d946800680193" + "2e",
}

const (
	// {"w": OrderedDict(a=[1.5, b"xy"]), "n": [0, 1, 2]}, protocol 4.
	benign4 = "8004954f000000000000007d94288c0177948c0b636f6c6c656374696f6e73948c0b4f726465726564446963749493942952948c0161945d9428473ff8000000000000430278799465738c016e945d94284b004b014b0265752e"
	// OrderedDict(a=1), protocol 2.
	benign2 = "800263636f6c6c656374696f6e730a4f726465726564446963740a71002952710158010000006171024b01732e"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPickleImports(t *testing.T) {
	for name, h := range evilPickles {
		imports, err := pickleImports(bytes.NewReader(unhex(t, h)))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		found := false
		for _, imp := range imports {
			found = found || dangerousImport(imp)
		}
		if !found {
			t.Errorf("%s: imports %v, want a dangerous one", name, imports)
		}
	}

	imports, err := pickleImports(bytes.NewReader(unhex(t, benign4)))
	if err != nil || !reflect.DeepEqual(imports, []string{"collections.OrderedDict"}) {
		t.Errorf("benign protocol 4: got %v, %v", imports, err)
	}

	// Two concatenated pickles, like PyTorch's legacy format, followed by raw data.
	legacy := append(unhex(t, benign2), unhex(t, evilPickles["protocol 2"])...)
	legacy = append(legacy, "raw tensor bytes"...)
	imports, err = pickleImports(bytes.NewReader(legacy))
	if err != nil || len(imports) != 2 || imports[1] != "os.system" {
		t.Errorf("concatenated: got %v, %v", imports, err)
	}

	if _, err := pickleImports(strings.NewReader("\x80\x04\x8c\x05ab")); err == nil {
		t.Error("truncated pickle: want an error")
	}
}

func TestDangerousImport(t *testing.T) {
	for imp, want := range map[string]bool{
		"os.system":                              true,
		"posix.system":                           true,
		"subprocess.Popen":                       true,
		"builtins.eval":                          true,
		"__builtin__.getattr":                    true,
		"operator.attrgetter":                    true,
		"builtins.set":                           false,
		"collections.OrderedDict":                false,
		"torch._utils._rebuild_tensor_v2":        false,
		"numpy.core.multiarray._reconstruct":     false,
		"sklearn.linear_model._base.LinearModel": false,
		"?":                                      false,
	} {
		if got := dangerousImport(imp); got != want {
			t.Errorf("dangerousImport(%q) = %v, want %v", imp, got, want)
		}
	}
}

func writeFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func torchZip(t *testing.T, pickle []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{"archive/data.pkl": pickle, "archive/data/0": []byte("weights"), "archive/version": []byte("3\n")} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rules(r *Report) map[string][]string {
	out := map[string][]string{}
	for _, is := range r.Issues {
		out[is.File] = append(out[is.File], is.Rule)
	}
	return out
}

func TestScanModels(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "models/evil.pkl", unhex(t, evilPickles["protocol 4"]))
	writeFile(t, dir, "models/weights.pkl", unhex(t, benign4))
	writeFile(t, dir, "models/evil.pt", torchZip(t, unhex(t, evilPickles["protocol 2"])))
	writeFile(t, dir, "models/ok.pt", torchZip(t, unhex(t, benign2)))
	writeFile(t, dir, "models/model.safetensors", []byte("{}"))
	writeFile(t, dir, "models/broken.pkl", []byte("\x80\x04\x8c\x05ab"))
	writeFile(t, dir, "data/blob.bin", []byte("not a model"))
	writeFile(t, dir, "node_modules/x/evil.pkl", unhex(t, evilPickles["protocol 0"]))

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"models/evil.pkl":    {"model-code-execution"},
		"models/evil.pt":     {"model-code-execution"},
		"models/weights.pkl": {"model-pickle-format"},
		"models/ok.pt":       {"model-pickle-format"},
		"models/broken.pkl":  {"model-unverified"},
	}
	if got := rules(r); !reflect.DeepEqual(got, want) {
		t.Errorf("issues = %v, want %v", got, want)
	}
	if r.Issues[0].Severity != "CRITICAL" {
		t.Errorf("first issue = %+v, want CRITICAL first", r.Issues[0])
	}
	if len(r.Models) != 6 {
		t.Errorf("models = %+v, want 6 (not blob.bin or node_modules)", r.Models)
	}
}

func TestScanMCP(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".mcp.json", []byte(`{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_0123456789abcdefghijklmnopqrstuvwxyz"}
    },
    "pinned": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "."],
      "env": {"API_KEY": "${API_KEY}", "TOKEN_FILE": "/run/secrets/token"}
    },
    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
    "fetch-pinned": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
    "remote": {"url": "http://mcp.example.com/sse", "headers": {"Authorization": "Bearer ${MCP_TOKEN}"}},
    "local": {"url": "http://localhost:3000/mcp"},
    "docker": {"command": "docker", "args": ["run", "-i", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-e", "X", "ghcr.io/acme/mcp"]},
    "docker-pinned": {"command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/acme/mcp:1.2.0"]},
    "installer": {"command": "bash", "args": ["-c", "curl -fsSL https://example.com/install.sh | sh && acme-mcp"]},
    "keyed": {"command": "acme-mcp", "args": ["--api-key", "a8f3k2m9q7w1z5x0"]}
  }
}`))
	// VS Code: "servers" key, comments and trailing commas.
	writeFile(t, dir, ".vscode/mcp.json", []byte(`{
  // GitHub's remote server
  "servers": {
    "gh": {"type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": {"Authorization": "Bearer ${input:token}"},},
  },
}`))

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, is := range r.Issues {
		got[is.Title] = true
		if strings.Contains(is.Title, "ghp_") || strings.Contains(is.Fix, "ghp_") {
			t.Errorf("issue leaks the secret: %+v", is)
		}
	}
	for _, want := range []string{
		`MCP server "github": env GITHUB_PERSONAL_ACCESS_TOKEN holds a literal secret`,
		`MCP server "github": runs @modelcontextprotocol/server-github without a pinned version`,
		`MCP server "fetch": runs mcp-server-fetch without a pinned version`,
		`MCP server "remote": remote server over plain HTTP`,
		`MCP server "docker": container runs with mounts the Docker socket`,
		`MCP server "docker": runs image ghcr.io/acme/mcp without a pinned version`,
		`MCP server "installer": downloads and runs a script on every start`,
		`MCP server "keyed": argument 2 holds a literal secret`,
	} {
		if !got[want] {
			t.Errorf("missing issue %q", want)
		}
	}
	if len(r.Issues) != 8 {
		for _, is := range r.Issues {
			t.Logf("%s: %s", is.File, is.Title)
		}
		t.Errorf("got %d issues, want 8", len(r.Issues))
	}
	if len(r.MCPServers) != 11 {
		t.Errorf("got %d MCP servers, want 11", len(r.MCPServers))
	}
}

func TestScanSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", []byte(`from transformers import AutoModel
model = AutoModel.from_pretrained("acme/model", trust_remote_code=True)
# trust_remote_code=True in a comment is fine
db = FAISS.load_local("index", emb, allow_dangerous_deserialization=True)
state = torch.load("w.pt", weights_only=False)
safe = torch.load("w.pt", weights_only=True)
`))
	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, is := range r.Issues {
		got = append(got, is.Rule+":"+string(rune('0'+is.Line)))
	}
	want := []string{"code-dangerous-deserialization:4", "code-trust-remote-code:2", "code-unsafe-torch-load:5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestComponents(t *testing.T) {
	pkgs := []inventory.Package{
		{Name: "OpenAI", Version: "1.40.0", Type: "python"},
		{Name: "langchain_core", Version: "0.3.1", Type: "python"},
		{Name: "@langchain/openai", Version: "0.2.0", Type: "npm"},
		{Name: "chromadb", Version: "0.5.0", Type: "python"},
		{Name: "chromadb", Version: "0.4.0", Type: "python"},
		{Name: "github.com/tmc/langchaingo", Version: "v0.1.12", Type: "go-module"},
		{Name: "django", Version: "4.2", Type: "python"},
		{Name: "openai", Version: "4.0.0", Type: "gem"},
	}
	got := Components(pkgs)
	want := []Component{
		{Category: AgentFramework, Name: "@langchain/openai", Ecosystem: "npm", Versions: []string{"0.2.0"}},
		{Category: AgentFramework, Name: "github.com/tmc/langchaingo", Ecosystem: "go-module", Versions: []string{"v0.1.12"}},
		{Category: AgentFramework, Name: "langchain_core", Ecosystem: "python", Versions: []string{"0.3.1"}},
		{Category: LLMAPI, Name: "OpenAI", Ecosystem: "python", Versions: []string{"1.40.0"}},
		{Category: VectorDB, Name: "chromadb", Ecosystem: "python", Versions: []string{"0.4.0", "0.5.0"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestIsLiteralSecret(t *testing.T) {
	for _, c := range []struct {
		name, value string
		want        bool
	}{
		{"GITHUB_TOKEN", "ghp_0123456789abcdefghijklmnopqrstuvwxyz", true},
		{"ANY", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz", true},
		{"API_KEY", "a8f3k2m9q7w1z5x0", true},
		{"API_KEY", "${API_KEY}", false},
		{"API_KEY", "${env:API_KEY}", false},
		{"API_KEY", "<your-api-key>", false},
		{"API_KEY", "YOUR_API_KEY_HERE", false},
		{"Authorization", "Bearer ${input:token}", false},
		{"GOOGLE_APPLICATION_CREDENTIALS", "/home/me/creds.json", false},
		{"LOG_LEVEL", "a8f3k2m9q7w1z5x0", false},
		{"AUTH_ENABLED", "true", false},
	} {
		if got := secret.Literal(c.name, c.value); got != c.want {
			t.Errorf("secret.Literal(%q, %q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
}
