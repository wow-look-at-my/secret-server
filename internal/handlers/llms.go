package handlers

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed llms.txt
var llmsTxt string

// RegisterLlms registers the public GET /llms.txt route: a plain-text guide
// to this server for LLMs/agents (https://llmstxt.org). Like /health it is
// served outside both Cloudflare Access groups; the CF Access application
// needs a path bypass for /llms.txt (like /github/*) for it to be publicly
// reachable.
func RegisterLlms(r chi.Router) {
	r.Get("/llms.txt", serveLlmsTxt)
}

// serveLlmsTxt renders the embedded guide, substituting {{BASE_URL}} with the
// scheme+host the request arrived on so the documented URLs always match the
// deployment. The scheme comes from X-Forwarded-Proto; the fallback is https
// because the server always sits behind a TLS-terminating proxy (cloudflared)
// in production.
func serveLlmsTxt(w http.ResponseWriter, r *http.Request) {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "https"
	}
	body := strings.ReplaceAll(llmsTxt, "{{BASE_URL}}", scheme+"://"+r.Host)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(body))
}
