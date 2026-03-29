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

	body := `{"key":"API_KEY","value":"secret","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader(body))
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
	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdateSecret(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret("KEY", "old", "app", "prod")

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"new","project":"app","environment":"prod"}`
	req := httptest.NewRequest("PUT", "/admin/v1/secrets/"+s.ID, strings.NewReader(body))
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
	s, _ := env.db.CreateSecret("KEY", "original", "app", "prod")

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"","project":"app","environment":"prod"}`
	req := httptest.NewRequest("PUT", "/admin/v1/secrets/"+s.ID, strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Equal(t, "original", got.Value)
}

func TestAdminPolicyCRUD(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_pattern":"org/*","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
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

	body = `{"name":"updated","repository_pattern":"org/*","ref_pattern":"*","project":"app","environment":"staging"}`
	req = httptest.NewRequest("PUT", "/admin/v1/policies/"+id, strings.NewReader(body))
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
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreatePolicyDefaultRefPattern(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_pattern":"org/*","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	policies, _ := env.db.ListPolicies()
	assert.Equal(t, "*", policies[0].RefPattern)
}

func TestAdminUpdateNonexistentSecret(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"val","project":"app","environment":"prod"}`
	req := httptest.NewRequest("PUT", "/admin/v1/secrets/nonexistent", strings.NewReader(body))
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

	body := `{"name":"test","repository_pattern":"org/*","ref_pattern":"*","project":"app","environment":"prod"}`
	req := httptest.NewRequest("PUT", "/admin/v1/policies/nonexistent", strings.NewReader(body))
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
	req = httptest.NewRequest("POST", "/admin/v1/environments", strings.NewReader(body))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]
	require.NotEmpty(t, id)

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
	req := httptest.NewRequest("POST", "/admin/v1/environments", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminDeleteEnvironmentInUse(t *testing.T) {
	env := setup(t)
	env.db.CreateSecret("KEY", "val", "app", "prod")

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	req := httptest.NewRequest("DELETE", "/admin/v1/environments/"+envID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusConflict, rr.Code)
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

	body := `{"key":"K","value":"v","project":"nonexistent","environment":"none"}`
	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdateSecretInvalidEnvironment(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret("KEY", "val", "app", "prod")
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"key":"KEY","value":"val","project":"nonexistent","environment":"none"}`
	req := httptest.NewRequest("PUT", "/admin/v1/secrets/"+s.ID, strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreatePolicyInvalidEnvironment(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_pattern":"org/*","project":"nonexistent","environment":"none"}`
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdatePolicyInvalidEnvironment(t *testing.T) {
	env := setup(t)
	p, _ := env.db.CreatePolicy("test", "org/*", "*", "app", "prod")
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_pattern":"org/*","ref_pattern":"*","project":"nonexistent","environment":"none"}`
	req := httptest.NewRequest("PUT", "/admin/v1/policies/"+p.ID, strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminEnvironmentInvalidJSON(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/v1/environments", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminInvalidJSON(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader("not json"))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = httptest.NewRequest("PUT", "/admin/v1/secrets/someid", strings.NewReader("not json"))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = httptest.NewRequest("PUT", "/admin/v1/policies/someid", strings.NewReader("not json"))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
