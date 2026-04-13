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
	env.db.CreatePolicy("allow", "", []string{"myorg/*"}, []string{"*"}, []string{"*"}, "", envID)

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
	env.db.CreatePolicy("other", "", []string{"otherorg/*"}, []string{"*"}, []string{"*"}, "", envID)

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
	env.db.CreatePolicy("p1", "", []string{"myorg/*"}, []string{"*"}, []string{"*"}, "", envID)
	env.db.CreatePolicy("p2", "", []string{"myorg/*"}, []string{"refs/heads/*"}, []string{"*"}, "", envID)

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
	env.db.CreatePolicy("p1", "", []string{"myorg/*"}, []string{"*"}, []string{"*"}, "", envProd)
	env.db.CreatePolicy("p2", "", []string{"myorg/*"}, []string{"*"}, []string{"*"}, "", envStaging)

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
	env.db.CreatePolicy("allow-deployer", "", []string{"myorg/*"}, []string{"*"}, []string{"deploy-*"}, "", envID)

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
	env.db.CreatePolicy("allow-deployer", "", []string{"myorg/*"}, []string{"*"}, []string{"deploy-*"}, "", envID)

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

func TestPublicFetchSecretsGitHubEnvMode(t *testing.T) {
	env := setup(t)

	envID := env.envID(t, "myapp", "prod")
	env.db.CreateSecret("API_KEY", "sk-live-123", envID)
	env.db.CreatePolicy("ghenv", "github-environment", []string{"myorg/*"}, nil, nil, "production", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	// Token with matching environment claim
	token := makeOIDCTokenWithEnv(t, env.jwk, "myorg/repo", "refs/heads/feature", "production")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
	assert.Equal(t, "sk-live-123", result["API_KEY"])
}

func TestPublicFetchSecretsGitHubEnvModeNoMatch(t *testing.T) {
	env := setup(t)

	envID := env.envID(t, "myapp", "prod")
	env.db.CreateSecret("API_KEY", "sk-live-123", envID)
	env.db.CreatePolicy("ghenv", "github-environment", []string{"myorg/*"}, nil, nil, "production", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	// Token with wrong environment claim
	token := makeOIDCTokenWithEnv(t, env.jwk, "myorg/repo", "refs/heads/main", "staging")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "{}", strings.TrimSpace(rr.Body.String()))
}

func TestPublicFetchSecretsGitHubEnvModeNoEnvClaim(t *testing.T) {
	env := setup(t)

	envID := env.envID(t, "myapp", "prod")
	env.db.CreateSecret("API_KEY", "sk-live-123", envID)
	env.db.CreatePolicy("ghenv", "github-environment", []string{"myorg/*"}, nil, nil, "production", envID)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	// Token without environment claim (standard makeOIDCToken)
	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "{}", strings.TrimSpace(rr.Body.String()))
}
