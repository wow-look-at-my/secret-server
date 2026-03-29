package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestPublicFetchSecretsNoToken(t *testing.T) {
	env := setup(t)
	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/github/v1/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestPublicFetchSecretsWithPolicy(t *testing.T) {
	env := setup(t)

	env.db.CreateSecret("DB_URL", "postgres://localhost", "myapp", "prod")
	env.db.CreatePolicy("allow", "myorg/*", "*", "myapp", "prod")

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("POST", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))

	assert.Equal(t, "postgres://localhost", result["DB_URL"])

	// Verify audit entry for secret access
	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access", entries[0].Action)
	assert.Equal(t, "github_actions", entries[0].ActorType)
	assert.Equal(t, "myorg/repo", entries[0].ActorID)
}

func TestPublicFetchSecretsNoMatchingPolicy(t *testing.T) {
	env := setup(t)
	env.db.CreateSecret("KEY", "val", "app", "prod")
	env.db.CreatePolicy("other", "otherorg/*", "*", "app", "prod")

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("POST", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "{}", strings.TrimSpace(rr.Body.String()))
}

func TestPublicFetchSecretsInvalidToken(t *testing.T) {
	env := setup(t)
	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token")
}

func TestPublicFetchSecretsMultiplePoliciesSameProjectEnv(t *testing.T) {
	env := setup(t)

	env.db.CreateSecret("KEY1", "val1", "app", "prod")
	env.db.CreateSecret("KEY2", "val2", "app", "prod")
	env.db.CreatePolicy("p1", "myorg/*", "*", "app", "prod")
	env.db.CreatePolicy("p2", "myorg/*", "refs/heads/*", "app", "prod")

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("POST", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
	assert.Equal(t, "val1", result["KEY1"])
	assert.Equal(t, "val2", result["KEY2"])
}

func TestPublicFetchSecretsMultipleProjectEnvs(t *testing.T) {
	env := setup(t)

	env.db.CreateSecret("KEY_A", "a", "app", "prod")
	env.db.CreateSecret("KEY_B", "b", "app", "staging")
	env.db.CreatePolicy("p1", "myorg/*", "*", "app", "prod")
	env.db.CreatePolicy("p2", "myorg/*", "*", "app", "staging")

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("POST", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
	assert.Equal(t, "a", result["KEY_A"])
	assert.Equal(t, "b", result["KEY_B"])
}
