package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func llmsMux() chi.Router {
	mux := chi.NewRouter()
	RegisterLlms(mux)
	return mux
}

func TestLlmsTxt(t *testing.T) {
	mux := llmsMux()

	req := httptest.NewRequest("GET", "/llms.txt", nil)
	req.Host = "secrets.example.com"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))

	body := rr.Body.String()
	// The placeholder must never leak into the served document.
	assert.NotContains(t, body, "{{BASE_URL}}")
	// Default scheme is https (the server sits behind cloudflared in prod).
	assert.Contains(t, body, "https://secrets.example.com/github/v1/secrets")

	// Key content markers: title, both credential types, the policy model,
	// and the GitHub Actions snippet.
	assert.True(t, strings.HasPrefix(body, "# secret-server\n"))
	assert.Contains(t, body, "sst_")
	assert.Contains(t, body, "GLOB")
	assert.Contains(t, body, "id-token: write")
	assert.Contains(t, body, "Cloudflare Access")
}

func TestLlmsTxtForwardedProto(t *testing.T) {
	mux := llmsMux()

	req := httptest.NewRequest("GET", "/llms.txt", nil)
	req.Host = "localhost:8080"
	req.Header.Set("X-Forwarded-Proto", "http")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "http://localhost:8080/github/v1/secrets")
}
