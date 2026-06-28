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

// attachSecretViaPolicy creates a group + secret, a policy, attaches the policy
// to the group, and returns the policy ID. Mirrors how the OIDC tests wire a
// secret to a policy.
func attachSecretViaPolicy(t *testing.T, env *testEnv, secretName, value string) string {
	t.Helper()
	g, err := env.db.CreateGroup(nil, "grp-"+secretName)
	require.Nil(t, err)
	gID := g.ID()
	_, err = env.db.CreateSecret(&gID, secretName, value)
	require.Nil(t, err)
	p, err := env.db.CreatePolicy("pol-"+secretName, []string{"*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)
	require.Nil(t, env.db.AttachPolicy(gID, p.ID))
	return p.ID
}

func TestPublicFetchSecretsMachineToken(t *testing.T) {
	env := setup(t)
	policyID := attachSecretViaPolicy(t, env, "GITHUB_APP_PRIVATE_KEY", "PEMDATA")
	token, _, err := env.db.CreateMachineToken("pr-minder-reconcile", policyID)
	require.NoError(t, err)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
	assert.Equal(t, "PEMDATA", result["GITHUB_APP_PRIVATE_KEY"])

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access.granted", entries[0].Action)
	assert.Equal(t, "machine_token", entries[0].ActorType)
	assert.Equal(t, "pr-minder-reconcile", entries[0].ActorID)
	assert.NotContains(t, entries[0].Details, token, "the token must never appear in the audit log")
}

func TestPublicFetchSecretsMachineTokenInvalid(t *testing.T) {
	env := setup(t)
	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer sst_not-a-real-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.access.denied", entries[0].Action)
	assert.Equal(t, "machine_token", entries[0].ActorType)
	assert.Contains(t, entries[0].Details, "invalid_machine_token")
}

func TestPublicFetchSecretsMachineTokenRevoked(t *testing.T) {
	env := setup(t)
	policyID := attachSecretViaPolicy(t, env, "K", "v")
	token, rec, err := env.db.CreateMachineToken("temp", policyID)
	require.NoError(t, err)
	require.NoError(t, env.db.DeleteMachineToken(rec.ID))

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAdminMachineTokenLifecycle(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	policyID := attachSecretViaPolicy(t, env, "X", "y")

	body := `{"name":"reconcile","policy_id":"` + policyID + `"}`
	req := jsonReq("POST", "/admin/v1/machine-tokens", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	id := created["id"]
	token := created["token"]
	require.NotEmpty(t, id)
	assert.True(t, strings.HasPrefix(token, "sst_"), "minted token should carry the sst_ prefix")

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "machine_token.create", entries[0].Action)
	assert.Equal(t, id, entries[0].ResourceID)

	// The minted token actually vends the policy's secret via the public endpoint.
	ph := NewPublicHandler(env.db, env.audit, env.oidc)
	pmux := chi.NewRouter()
	ph.Register(pmux)
	preq := httptest.NewRequest("GET", "/github/v1/secrets", nil)
	preq.Header.Set("Authorization", "Bearer "+token)
	prr := httptest.NewRecorder()
	pmux.ServeHTTP(prr, preq)
	require.Equal(t, http.StatusOK, prr.Code)
	var vended map[string]string
	require.NoError(t, json.Unmarshal(prr.Body.Bytes(), &vended))
	assert.Equal(t, "y", vended["X"])

	// Listing shows it by name/prefix but never leaks the full token.
	req = httptest.NewRequest("GET", "/admin/v1/machine-tokens", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "reconcile")
	assert.NotContains(t, rr.Body.String(), token)

	// Revoke it.
	req = httptest.NewRequest("DELETE", "/admin/v1/machine-tokens/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminCreateMachineTokenMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := jsonReq("POST", "/admin/v1/machine-tokens", `{"name":"x"}`)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreateMachineTokenUnknownPolicy(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"x","policy_id":"00000000-0000-0000-0000-000000000000"}`
	req := jsonReq("POST", "/admin/v1/machine-tokens", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
