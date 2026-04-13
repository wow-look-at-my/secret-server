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

func TestAdminCreateAndDeleteSecret(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	body := `{"key":"API_KEY","value":"secret","environment_id":"` + envID + `"}`
	req := jsonReq("POST", "/admin/v1/secrets", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	// Verify audit entry for create
	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.create", entries[0].Action)
	assert.Equal(t, "secret", entries[0].ResourceType)
	assert.Equal(t, id, entries[0].ResourceID)

	req = httptest.NewRequest("DELETE", "/admin/v1/secrets/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify audit entry for delete
	entries, err = env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 2, len(entries))
	assert.Equal(t, "secret.delete", entries[0].Action)
	assert.Equal(t, id, entries[0].ResourceID)
}

func TestAdminCreateSecretMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"API_KEY"}`
	req := jsonReq("POST", "/admin/v1/secrets", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdateSecret(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	s, _ := env.db.CreateSecret("KEY", "old", envID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"new","environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/secrets/"+s.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Equal(t, "new", got.Value)

	// Verify audit entry for update
	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "secret.update", entries[0].Action)
	assert.Equal(t, s.ID, entries[0].ResourceID)
}

func TestAdminUpdateSecretEmptyValuePreservesExisting(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	s, _ := env.db.CreateSecret("KEY", "original", envID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"","environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/secrets/"+s.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Equal(t, "original", got.Value)
}

func TestAdminUpdateSecretEmptyValueNotFound(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"","environment_id":"00000000-0000-0000-0000-000000000000"}`
	req := jsonReq("PUT", "/admin/v1/secrets/nonexistent", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminPolicyCRUD(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envIDProd := env.envID(t, "app", "prod")
	envIDStaging := env.envID(t, "app", "staging")

	body := `{"name":"test","repository_patterns":["org/*"],"environment_id":"` + envIDProd + `"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	// Verify audit entry for policy create
	entries, _ := env.audit.ListEntries(10, 0)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "policy.create", entries[0].Action)
	assert.Equal(t, id, entries[0].ResourceID)

	body = `{"name":"updated","repository_patterns":["org/*"],"ref_patterns":["*"],"environment_id":"` + envIDStaging + `"}`
	req = jsonReq("PUT", "/admin/v1/policies/"+id, body)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify audit entry for policy update
	entries, _ = env.audit.ListEntries(10, 0)
	require.Equal(t, 2, len(entries))
	assert.Equal(t, "policy.update", entries[0].Action)

	req = httptest.NewRequest("DELETE", "/admin/v1/policies/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify audit entry for policy delete
	entries, _ = env.audit.ListEntries(10, 0)
	require.Equal(t, 3, len(entries))
	assert.Equal(t, "policy.delete", entries[0].Action)
}

func TestAdminCreatePolicyMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreatePolicyDefaultRefPattern(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	body := `{"name":"test","repository_patterns":["org/*"],"environment_id":"` + envID + `"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	policies, _ := env.db.ListPolicies()
	assert.Equal(t, []string{"*"}, policies[0].RefPatterns)
	assert.Equal(t, []string{"*"}, policies[0].ActorPatterns)
}

func TestAdminCreatePolicyMultiplePatterns(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	body := `{"name":"multi","repository_patterns":["org/api-*","org/worker-*"],"ref_patterns":["refs/heads/main","refs/tags/v*"],"actor_patterns":["deploy-*"],"environment_id":"` + envID + `"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	policies, _ := env.db.ListPolicies()
	require.Equal(t, 1, len(policies))
	assert.Equal(t, []string{"org/api-*", "org/worker-*"}, policies[0].RepositoryPatterns)
	assert.Equal(t, []string{"refs/heads/main", "refs/tags/v*"}, policies[0].RefPatterns)
	assert.Equal(t, []string{"deploy-*"}, policies[0].ActorPatterns)
}

func TestAdminCreatePolicyInvalidGlob(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	body := `{"name":"bad","repository_patterns":["org/["],"environment_id":"` + envID + `"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid glob pattern")
}

func TestAdminUpdatePolicyMultiPattern(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	p, _ := env.db.CreatePolicy("test", "", []string{"org/*"}, []string{"*"}, []string{"*"}, "", envID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"updated","repository_patterns":["org/a","org/b"],"ref_patterns":["refs/heads/main","refs/tags/v*"],"actor_patterns":["deploy-*"],"environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/policies/"+p.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetPolicy(p.ID)
	assert.Equal(t, "updated", got.Name)
	assert.Equal(t, []string{"org/a", "org/b"}, got.RepositoryPatterns)
	assert.Equal(t, []string{"refs/heads/main", "refs/tags/v*"}, got.RefPatterns)
	assert.Equal(t, []string{"deploy-*"}, got.ActorPatterns)
}

func TestAdminUpdatePolicyEmptyRepoPatterns(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	p, _ := env.db.CreatePolicy("test", "", []string{"org/*"}, []string{"*"}, []string{"*"}, "", envID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"updated","repository_patterns":[],"environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/policies/"+p.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "repository_patterns must not be empty")
}

func TestAdminUpdatePolicyInvalidGlob(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	p, _ := env.db.CreatePolicy("test", "", []string{"org/*"}, []string{"*"}, []string{"*"}, "", envID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"updated","repository_patterns":["org/["],"environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/policies/"+p.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid glob pattern")
}

func TestAdminUpdateNonexistentSecret(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	body := `{"key":"KEY","value":"val","environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/secrets/nonexistent", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminDeleteNonexistentSecret(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/secrets/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminUpdateNonexistentPolicy(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	body := `{"name":"test","repository_patterns":["org/*"],"ref_patterns":["*"],"environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/policies/nonexistent", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminDeleteNonexistentPolicy(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/policies/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminEnvironmentCRUD(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// List environments (pre-seeded by setup)
	req := httptest.NewRequest("GET", "/admin/v1/environments", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Create new environment
	body := `{"project":"newapp","environment":"staging"}`
	req = jsonReq("POST", "/admin/v1/environments", body)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]
	require.NotEmpty(t, id)

	// Update it
	body = `{"project":"newapp","environment":"production"}`
	req = jsonReq("PUT", "/admin/v1/environments/"+id, body)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetEnvironment(id)
	assert.Equal(t, "production", got.Environment)

	// Delete it (not in use)
	req = httptest.NewRequest("DELETE", "/admin/v1/environments/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminCreateEnvironmentMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"project":"app"}`
	req := jsonReq("POST", "/admin/v1/environments", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminDeleteEnvironmentInUse(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	env.db.CreateSecret("KEY", "val", envID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/environments/"+envID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestAdminDeleteEnvironmentSuccess(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// "other/prod" is pre-created but has no secrets or policies referencing it.
	envID := env.envID(t, "other", "prod")
	req := httptest.NewRequest("DELETE", "/admin/v1/environments/"+envID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminDeleteEnvironmentNotFound(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/environments/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminCreateSecretInvalidEnvironment(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"K","value":"v","environment_id":"nonexistent-id"}`
	req := jsonReq("POST", "/admin/v1/secrets", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdateSecretInvalidEnvironment(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	s, _ := env.db.CreateSecret("KEY", "val", envID)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"val","environment_id":"nonexistent-id"}`
	req := jsonReq("PUT", "/admin/v1/secrets/"+s.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreatePolicyInvalidEnvironment(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_patterns":["org/*"],"environment_id":"nonexistent-id"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdatePolicyInvalidEnvironment(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	p, _ := env.db.CreatePolicy("test", "", []string{"org/*"}, []string{"*"}, []string{"*"}, "", envID)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_patterns":["org/*"],"ref_patterns":["*"],"environment_id":"nonexistent-id"}`
	req := jsonReq("PUT", "/admin/v1/policies/"+p.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminEnvironmentInvalidJSON(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := jsonReq("POST", "/admin/v1/environments", "not json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminInvalidJSON(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := jsonReq("POST", "/admin/v1/secrets", "not json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = jsonReq("POST", "/admin/v1/policies", "not json")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = jsonReq("PUT", "/admin/v1/secrets/someid", "not json")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = jsonReq("PUT", "/admin/v1/policies/someid", "not json")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdateEnvironmentNotFound(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"project":"app","environment":"prod"}`
	req := jsonReq("PUT", "/admin/v1/environments/nonexistent", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminUpdateEnvironmentMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	body := `{"project":"app"}`
	req := jsonReq("PUT", "/admin/v1/environments/"+envID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdateEnvironmentInvalidJSON(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	req := jsonReq("PUT", "/admin/v1/environments/"+envID, "not json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminDeleteEnvironmentDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/environments/some-id", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminCreateSecretDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := "00000000-0000-0000-0000-000000000000"
	body := `{"key":"K","value":"v","environment_id":"` + envID + `"}`
	req := jsonReq("POST", "/admin/v1/secrets", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminCreatePolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := "00000000-0000-0000-0000-000000000000"
	body := `{"name":"test","repository_patterns":["org/*"],"environment_id":"` + envID + `"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminUpdateSecretDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := "00000000-0000-0000-0000-000000000000"
	body := `{"key":"K","value":"v","environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/secrets/someid", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminUpdatePolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := "00000000-0000-0000-0000-000000000000"
	body := `{"name":"t","repository_patterns":["org/*"],"ref_patterns":["*"],"environment_id":"` + envID + `"}`
	req := jsonReq("PUT", "/admin/v1/policies/someid", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminListEnvironmentsDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/environments", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminRequiresJSONContentType(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	endpoints := []struct {
		method string
		path   string
	}{
		{"POST", "/admin/v1/secrets"},
		{"PUT", "/admin/v1/secrets/someid"},
		{"POST", "/admin/v1/policies"},
		{"PUT", "/admin/v1/policies/someid"},
		{"POST", "/admin/v1/environments"},
		{"PUT", "/admin/v1/environments/someid"},
	}

	for _, ep := range endpoints {
		// Request without Content-Type header should be rejected.
		req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code, "%s %s", ep.method, ep.path)
	}
}
