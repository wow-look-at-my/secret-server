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

	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access.denied", entries[0].Action)
	assert.Equal(t, "anonymous", entries[0].ActorType)
	assert.Equal(t, "unknown", entries[0].ActorID)
	assert.Contains(t, entries[0].Details, `"reason":"missing_token"`)
}

func TestPublicFetchSecretsWithPolicy(t *testing.T) {
	env := setup(t)

	envID := env.envID(t, "myapp", "prod")
	env.db.CreateSecret("DB_URL", "postgres://localhost", envID)
	env.db.CreatePolicy("allow", "myorg/*", "*", "*", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
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
	envID := env.envID(t, "app", "prod")
	env.db.CreateSecret("KEY", "val", envID)
	env.db.CreatePolicy("other", "otherorg/*", "*", "*", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "{}", strings.TrimSpace(rr.Body.String()))

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access.denied", entries[0].Action)
	assert.Equal(t, "github_actions", entries[0].ActorType)
	assert.Equal(t, "myorg/repo", entries[0].ActorID)
	assert.Contains(t, entries[0].Details, `"reason":"no_matching_policies"`)
	assert.Contains(t, entries[0].Details, `"repository":"myorg/repo"`)
}

func TestPublicFetchSecretsInvalidToken(t *testing.T) {
	env := setup(t)
	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token")

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access.denied", entries[0].Action)
	assert.Equal(t, "anonymous", entries[0].ActorType)
	assert.Contains(t, entries[0].Details, `"reason":"invalid_token"`)
}

func TestPublicFetchSecretsPolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access.denied", entries[0].Action)
	assert.Equal(t, "github_actions", entries[0].ActorType)
	assert.Equal(t, "myorg/repo", entries[0].ActorID)
	assert.Contains(t, entries[0].Details, `"reason":"policy_lookup_error"`)
}

func TestPublicFetchSecretsMultiplePoliciesSameProjectEnv(t *testing.T) {
	env := setup(t)

	envID := env.envID(t, "app", "prod")
	env.db.CreateSecret("KEY1", "val1", envID)
	env.db.CreateSecret("KEY2", "val2", envID)
	env.db.CreatePolicy("p1", "myorg/*", "*", "*", envID)
	env.db.CreatePolicy("p2", "myorg/*", "refs/heads/*", "*", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
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

	envProd := env.envID(t, "app", "prod")
	envStaging := env.envID(t, "app", "staging")
	env.db.CreateSecret("KEY_A", "a", envProd)
	env.db.CreateSecret("KEY_B", "b", envStaging)
	env.db.CreatePolicy("p1", "myorg/*", "*", "*", envProd)
	env.db.CreatePolicy("p2", "myorg/*", "*", "*", envStaging)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
	assert.Equal(t, "a", result["KEY_A"])
	assert.Equal(t, "b", result["KEY_B"])
}

func TestPublicFetchSecretsActorPatternMatch(t *testing.T) {
	env := setup(t)

	envID := env.envID(t, "myapp", "prod")
	env.db.CreateSecret("DB_URL", "postgres://localhost", envID)
	env.db.CreatePolicy("allow-deployer", "myorg/*", "*", "deploy-*", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	// Actor matches the pattern
	token := makeOIDCTokenWithActor(t, env.jwk, "myorg/repo", "refs/heads/main", "deploy-bot")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
	assert.Equal(t, "postgres://localhost", result["DB_URL"])
}

func TestPublicFetchSecretsActorPatternNoMatch(t *testing.T) {
	env := setup(t)

	envID := env.envID(t, "myapp", "prod")
	env.db.CreateSecret("DB_URL", "postgres://localhost", envID)
	env.db.CreatePolicy("allow-deployer", "myorg/*", "*", "deploy-*", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	// Actor does NOT match the pattern
	token := makeOIDCTokenWithActor(t, env.jwk, "myorg/repo", "refs/heads/main", "random-user")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "{}", strings.TrimSpace(rr.Body.String()))
}
