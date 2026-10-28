package aistack

import (
	"sort"
	"strings"

	"github.com/hardenkit/scan/internal/inventory"
)

// Component categories.
const (
	LLMAPI          = "LLM API"
	AgentFramework  = "Agent framework"
	VectorDB        = "Vector database"
	MLFramework     = "ML framework"
	MCPSDK          = "MCP SDK"
	ModelHub        = "Model hub"
	InferenceServer = "Inference server"
)

// Component is one AI-related package the project depends on.
type Component struct {
	Category  string   `json:"category"`
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem"`
	Versions  []string `json:"versions"`
}

// catalog maps "<syft package type>/<normalized name>" to a category.
// Names ending in "/" match every package with that prefix (npm scopes).
var catalog = map[string]string{
	// Python
	"python/openai":                  LLMAPI,
	"python/anthropic":               LLMAPI,
	"python/google-genai":            LLMAPI,
	"python/google-generativeai":     LLMAPI,
	"python/google-cloud-aiplatform": LLMAPI,
	"python/mistralai":               LLMAPI,
	"python/cohere":                  LLMAPI,
	"python/groq":                    LLMAPI,
	"python/together":                LLMAPI,
	"python/ollama":                  LLMAPI,
	"python/litellm":                 LLMAPI,
	"python/langchain":               AgentFramework,
	"python/langchain-core":          AgentFramework,
	"python/langchain-community":     AgentFramework,
	"python/langchain-experimental":  AgentFramework,
	"python/langgraph":               AgentFramework,
	"python/llama-index":             AgentFramework,
	"python/llama-index-core":        AgentFramework,
	"python/crewai":                  AgentFramework,
	"python/autogen":                 AgentFramework,
	"python/pyautogen":               AgentFramework,
	"python/autogen-agentchat":       AgentFramework,
	"python/ag2":                     AgentFramework,
	"python/semantic-kernel":         AgentFramework,
	"python/haystack-ai":             AgentFramework,
	"python/dspy":                    AgentFramework,
	"python/dspy-ai":                 AgentFramework,
	"python/pydantic-ai":             AgentFramework,
	"python/smolagents":              AgentFramework,
	"python/openai-agents":           AgentFramework,
	"python/claude-agent-sdk":        AgentFramework,
	"python/instructor":              AgentFramework,
	"python/chromadb":                VectorDB,
	"python/pinecone":                VectorDB,
	"python/pinecone-client":         VectorDB,
	"python/qdrant-client":           VectorDB,
	"python/weaviate-client":         VectorDB,
	"python/pymilvus":                VectorDB,
	"python/lancedb":                 VectorDB,
	"python/faiss-cpu":               VectorDB,
	"python/faiss-gpu":               VectorDB,
	"python/pgvector":                VectorDB,
	"python/torch":                   MLFramework,
	"python/tensorflow":              MLFramework,
	"python/keras":                   MLFramework,
	"python/jax":                     MLFramework,
	"python/transformers":            MLFramework,
	"python/sentence-transformers":   MLFramework,
	"python/scikit-learn":            MLFramework,
	"python/onnxruntime":             MLFramework,
	"python/huggingface-hub":         ModelHub,
	"python/vllm":                    InferenceServer,
	"python/mcp":                     MCPSDK,
	"python/fastmcp":                 MCPSDK,

	// npm
	"npm/openai":                         LLMAPI,
	"npm/@anthropic-ai/sdk":              LLMAPI,
	"npm/@google/genai":                  LLMAPI,
	"npm/@google/generative-ai":          LLMAPI,
	"npm/@mistralai/mistralai":           LLMAPI,
	"npm/cohere-ai":                      LLMAPI,
	"npm/groq-sdk":                       LLMAPI,
	"npm/ollama":                         LLMAPI,
	"npm/ai":                             AgentFramework, // Vercel AI SDK
	"npm/@ai-sdk/":                       LLMAPI,
	"npm/langchain":                      AgentFramework,
	"npm/@langchain/":                    AgentFramework,
	"npm/llamaindex":                     AgentFramework,
	"npm/@mastra/core":                   AgentFramework,
	"npm/@openai/agents":                 AgentFramework,
	"npm/@anthropic-ai/claude-agent-sdk": AgentFramework,
	"npm/@pinecone-database/pinecone":    VectorDB,
	"npm/chromadb":                       VectorDB,
	"npm/@qdrant/js-client-rest":         VectorDB,
	"npm/weaviate-client":                VectorDB,
	"npm/@zilliz/milvus2-sdk-node":       VectorDB,
	"npm/@lancedb/lancedb":               VectorDB,
	"npm/@huggingface/inference":         ModelHub,
	"npm/@huggingface/transformers":      MLFramework,
	"npm/@xenova/transformers":           MLFramework,
	"npm/@modelcontextprotocol/sdk":      MCPSDK,

	// Go
	"go-module/github.com/openai/openai-go":            LLMAPI,
	"go-module/github.com/anthropics/anthropic-sdk-go": LLMAPI,
	"go-module/github.com/sashabaranov/go-openai":      LLMAPI,
	"go-module/google.golang.org/genai":                LLMAPI,
	"go-module/github.com/google/generative-ai-go":     LLMAPI,
	"go-module/github.com/ollama/ollama":               LLMAPI,
	"go-module/github.com/tmc/langchaingo":             AgentFramework,
	"go-module/github.com/firebase/genkit/go":          AgentFramework,
	"go-module/github.com/qdrant/go-client":            VectorDB,
	"go-module/github.com/pinecone-io/go-pinecone":     VectorDB,
	"go-module/github.com/weaviate/weaviate-go-client": VectorDB,
	"go-module/github.com/milvus-io/milvus-sdk-go":     VectorDB,
	"go-module/github.com/pgvector/pgvector-go":        VectorDB,
	"go-module/github.com/mark3labs/mcp-go":            MCPSDK,
	"go-module/github.com/modelcontextprotocol/go-sdk": MCPSDK,
}

// Components picks the AI-related packages out of pkgs, one entry per
// package with every version found, sorted by category and name.
func Components(pkgs []inventory.Package) []Component {
	byKey := map[string]*Component{}
	for _, p := range pkgs {
		name := normalize(p.Type, p.Name)
		cat := category(p.Type, name)
		if cat == "" {
			continue
		}
		key := p.Type + "/" + name
		c := byKey[key]
		if c == nil {
			c = &Component{Category: cat, Name: p.Name, Ecosystem: p.Type}
			byKey[key] = c
		}
		if p.Version != "" && !contains(c.Versions, p.Version) {
			c.Versions = append(c.Versions, p.Version)
		}
	}
	out := make([]Component, 0, len(byKey))
	for _, c := range byKey {
		sort.Strings(c.Versions)
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func category(typ, name string) string {
	key := typ + "/" + name
	if c, ok := catalog[key]; ok {
		return c
	}
	// Scoped npm packages such as @langchain/openai.
	if i := strings.Index(key, "/@"); i >= 0 {
		if j := strings.Index(key[i+2:], "/"); j >= 0 {
			if c, ok := catalog[key[:i+2+j+1]]; ok {
				return c
			}
		}
	}
	// Go submodules such as github.com/tmc/langchaingo/llms.
	if typ == "go-module" {
		for prefix, c := range catalog {
			if strings.HasPrefix(key, prefix+"/") {
				return c
			}
		}
	}
	return ""
}

// normalize applies the ecosystem's name rules: Python names are
// case-insensitive and treat "-", "_" and "." alike (PEP 503).
func normalize(typ, name string) string {
	if typ == "python" {
		return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name))
	}
	return name
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
