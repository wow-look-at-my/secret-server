package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attachPolicyTo is a small helper that creates a secret + policy and
// attaches them, returning the policy ID. Each test needs this shape so
// the inherited-downward walk actually finds anything.
func attachPolicyTo(t *testing.T, env *testEnv, secretName, value string, parentID *string,
	policyName string, repo, ref, actor []string) (secretID, policyID string) {
	t.Helper()
	s, err := env.db.CreateSecret(parentID, secretName, value)
	require.Nil(t, err)
	p, err := env.db.CreatePolicy(policyName, repo, ref, actor)
	require.Nil(t, err)
	require.Nil(t, env.db.AttachPolicy(s.ID(), p.ID))
	return s.ID(), p.ID
}

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
	attachPolicyTo(t, env, "DB_URL", "postgres://localhost", nil,
		"allow", []string{"myorg/*"}, []string{"*"}, []string{"*"})

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

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access.granted", entries[0].Action)
	assert.Equal(t, "github_actions", entries[0].ActorType)
	assert.Equal(t, "583231", entries[0].ActorID)
	assert.Contains(t, entries[0].Details, `"actor":"deploy-bot"`)
	assert.Contains(t, entries[0].Details, `"actor_id":"583231"`)
}

func TestPublicFetchSecretsNoMatchingPolicy(t *testing.T) {
	env := setup(t)
	attachPolicyTo(t, env, "KEY", "val", nil,
		"other", []string{"otherorg/*"}, []string{"*"}, []string{"*"})

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
	assert.Equal(t, "583231", entries[0].ActorID)
	assert.Contains(t, entries[0].Details, `"reason":"no_matching_policies"`)
	assert.Contains(t, entries[0].Details, `"repository":"myorg/repo"`)
}

// TestPublicFetchSecretsEmptyPolicyGrantsNoAccess is the security guard for
// allowing empty policies: an attached policy with no repository patterns must
// match nothing (the repository inner JOIN in MatchingPolicyIDs yields no rows)
// and therefore grant no secrets, even though it is attached to the secret.
func TestPublicFetchSecretsEmptyPolicyGrantsNoAccess(t *testing.T) {
	env := setup(t)
	// Empty repository patterns; ref/actor are wide open. Fail-closed because
	// the repository kind has zero pattern rows.
	attachPolicyTo(t, env, "KEY", "val", nil,
		"empty", nil, []string{"*"}, []string{"*"})

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
	assert.Contains(t, entries[0].Details, `"reason":"no_matching_policies"`)
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
	assert.Equal(t, "583231", entries[0].ActorID)
	assert.Contains(t, entries[0].Details, `"reason":"policy_lookup_error"`)
}

func TestPublicFetchSecretsMultipleSecretsSamePolicy(t *testing.T) {
	env := setup(t)

	// Attach the same policy to two different secrets (via a shared group).
	g, err := env.db.CreateGroup(nil, "shared")
	require.Nil(t, err)
	gID := g.ID()
	_, err = env.db.CreateSecret(&gID, "KEY1", "val1")
	require.Nil(t, err)
	_, err = env.db.CreateSecret(&gID, "KEY2", "val2")
	require.Nil(t, err)
	p, err := env.db.CreatePolicy("p", []string{"myorg/*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)
	require.Nil(t, env.db.AttachPolicy(gID, p.ID))

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

func TestPublicFetchSecretsInheritanceFromAncestor(t *testing.T) {
	// Policy attached to a group should grant access to every descendant
	// secret via the recursive CTE.
	env := setup(t)

	root, err := env.db.CreateGroup(nil, "root")
	require.Nil(t, err)
	rootID := root.ID()
	mid, err := env.db.CreateGroup(&rootID, "mid")
	require.Nil(t, err)
	midID := mid.ID()
	_, err = env.db.CreateSecret(&midID, "DEEP_SECRET", "deep-value")
	require.Nil(t, err)

	p, err := env.db.CreatePolicy("p", []string{"myorg/*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)
	// Attach to the top-level group.
	require.Nil(t, env.db.AttachPolicy(rootID, p.ID))

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
	assert.Equal(t, "deep-value", result["DEEP_SECRET"])
}

func TestPublicFetchSecretsActorPatternMatch(t *testing.T) {
	env := setup(t)
	attachPolicyTo(t, env, "DB_URL", "postgres://localhost", nil,
		"allow-deployer", []string{"myorg/*"}, []string{"*"}, []string{"deploy-*"})

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

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
	attachPolicyTo(t, env, "DB_URL", "postgres://localhost", nil,
		"allow-deployer", []string{"myorg/*"}, []string{"*"}, []string{"deploy-*"})

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	token := makeOIDCTokenWithActor(t, env.jwk, "myorg/repo", "refs/heads/main", "random-user")
	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "{}", strings.TrimSpace(rr.Body.String()))
}
