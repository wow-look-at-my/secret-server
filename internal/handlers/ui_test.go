package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestUIPages(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "app", "prod")
	env.db.CreateSecret("KEY", "val", envID)
	env.db.CreatePolicy("p", "org/*", "*", "*", envID)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	pages := []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/admin/", http.StatusOK},
		{"GET", "/admin/secrets", http.StatusOK},
		{"GET", "/admin/secrets?project=app", http.StatusOK},
		{"GET", "/admin/secrets/new", http.StatusOK},
		{"GET", "/admin/policies", http.StatusOK},
		{"GET", "/admin/policies/new", http.StatusOK},
		{"GET", "/admin/environments", http.StatusOK},
		{"GET", "/admin/environments/new", http.StatusOK},
	}

	for _, p := range pages {
		req := httptest.NewRequest(p.method, p.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(t, p.status, rr.Code)
	}
}

func TestUIAdminRedirect(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/admin/", rr.Header().Get("Location"))
}

func TestUISecretCreateEditDelete(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "testproj", "staging")

	form := "key=MY_KEY&value=my_secret&env_id=" + envID
	req := httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	secrets, _ := env.db.ListSecrets("testproj", "staging")
	require.Equal(t, 1, len(secrets))
	id := secrets[0].ID

	req = httptest.NewRequest("GET", "/admin/secrets/"+id+"/edit", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	form = "key=MY_KEY&value=updated_secret&env_id=" + envID
	req = httptest.NewRequest("POST", "/admin/secrets/"+id, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(id)
	assert.Equal(t, "updated_secret", got.Value)

	req = httptest.NewRequest("POST", "/admin/secrets/"+id+"/delete", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ = env.db.GetSecret(id)
	assert.Nil(t, got)
}

func TestUIPolicyCreateEditDelete(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	envIDProd := env.envID(t, "app", "prod")
	envIDStaging := env.envID(t, "app", "staging")

	form := "name=Test+Policy&repository_pattern=org/*&ref_pattern=*&env_id=" + envIDProd
	req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	policies, _ := env.db.ListPolicies()
	require.Equal(t, 1, len(policies))
	id := policies[0].ID

	req = httptest.NewRequest("GET", "/admin/policies/"+id+"/edit", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	form = "name=Updated+Policy&repository_pattern=org/*&ref_pattern=refs/heads/main&env_id=" + envIDStaging
	req = httptest.NewRequest("POST", "/admin/policies/"+id, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(id)
	assert.Equal(t, "Updated Policy", got.Name)
	assert.Equal(t, "staging", got.Environment)

	req = httptest.NewRequest("POST", "/admin/policies/"+id+"/delete", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ = env.db.GetPolicy(id)
	assert.Nil(t, got)
}

func TestUIEditSecretNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/nonexistent/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIUpdateNonexistentSecret(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	form := "key=K&value=v&env_id=" + envID
	req := httptest.NewRequest("POST", "/admin/secrets/nonexistent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIDeleteNonexistentSecret(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/nonexistent/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIUpdateNonexistentPolicy(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	form := "name=P&repository_pattern=org/*&ref_pattern=*&env_id=" + envID
	req := httptest.NewRequest("POST", "/admin/policies/nonexistent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIDeleteNonexistentPolicy(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/policies/nonexistent/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIEditPolicyNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/policies/nonexistent/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIPolicyCreateDefaultRefPattern(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	envID := env.envID(t, "app", "prod")
	form := "name=NoRef&repository_pattern=org/*&env_id=" + envID
	req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	policies, _ := env.db.ListPolicies()
	require.Equal(t, 1, len(policies))
	assert.Equal(t, "*", policies[0].RefPattern)
}

func TestUIDashboardRedirectBadPath(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/something-else", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/admin/", rr.Header().Get("Location"))
}

func TestUISecretCreateDuplicate(t *testing.T) {
	env := setup(t)
	envID := env.envID(t, "proj", "env")
	env.db.CreateSecret("DUP_KEY", "val", envID)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "key=DUP_KEY&value=val2&env_id=" + envID
	req := httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUIListSecretsWithEnvFilter(t *testing.T) {
	env := setup(t)
	envProd := env.envID(t, "proj", "prod")
	envDev := env.envID(t, "proj", "dev")
	env.db.CreateSecret("K1", "v1", envProd)
	env.db.CreateSecret("K2", "v2", envDev)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets?project=proj&environment=prod", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "K1")
}

func TestUIUpdatePolicyViaForm(t *testing.T) {
	env := setup(t)
	envProd := env.envID(t, "app", "prod")
	p, _ := env.db.CreatePolicy("test", "org/*", "*", "*", envProd)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	envStaging := env.envID(t, "app", "staging")
	form := "name=Updated&repository_pattern=org/*&ref_pattern=refs/heads/main&env_id=" + envStaging
	req := httptest.NewRequest("POST", "/admin/policies/"+p.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(p.ID)
	assert.Equal(t, "Updated", got.Name)
	assert.Equal(t, "refs/heads/main", got.RefPattern)
}

func TestUIUpdatePolicyDefaultRefPattern(t *testing.T) {
	env := setup(t)
	envProd := env.envID(t, "app", "prod")
	p, _ := env.db.CreatePolicy("test", "org/*", "refs/heads/main", "*", envProd)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=Updated&repository_pattern=org/*&env_id=" + envProd
	req := httptest.NewRequest("POST", "/admin/policies/"+p.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(p.ID)
	assert.Equal(t, "*", got.RefPattern)
}

func TestUIDeleteSecretViaForm(t *testing.T) {
	env := setup(t)
	envProd := env.envID(t, "app", "prod")
	s, _ := env.db.CreateSecret("DEL", "val", envProd)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/"+s.ID+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Nil(t, got)
}

func TestUIDeletePolicyViaForm(t *testing.T) {
	env := setup(t)
	envProd := env.envID(t, "app", "prod")
	p, _ := env.db.CreatePolicy("del", "org/*", "*", "*", envProd)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/policies/"+p.ID+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(p.ID)
	assert.Nil(t, got)
}

func TestUIUpdateSecretViaForm(t *testing.T) {
	env := setup(t)
	envProd := env.envID(t, "app", "prod")
	s, _ := env.db.CreateSecret("UPD", "old", envProd)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "key=UPD&value=new_val&env_id=" + envProd
	req := httptest.NewRequest("POST", "/admin/secrets/"+s.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Equal(t, "new_val", got.Value)
}

func TestUIUpdateSecretEmptyValuePreservesExisting(t *testing.T) {
	env := setup(t)
	envProd := env.envID(t, "app", "prod")
	s, _ := env.db.CreateSecret("KEEP", "original_secret", envProd)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "key=KEEP&value=&env_id=" + envProd
	req := httptest.NewRequest("POST", "/admin/secrets/"+s.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Equal(t, "original_secret", got.Value)
}

// DB error tests use a closed database to trigger error paths.

func TestUICreateSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "key=K&value=v&env_id=some-id"
	req := httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUIUpdateSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "key=K&value=v&env_id=some-id"
	req := httptest.NewRequest("POST", "/admin/secrets/some-id", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUICreatePolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=P&repository_pattern=org/*&ref_pattern=*&env_id=some-id"
	req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUIUpdatePolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=P&repository_pattern=org/*&ref_pattern=*&env_id=some-id"
	req := httptest.NewRequest("POST", "/admin/policies/some-id", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIListSecretsDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIListPoliciesDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDashboardDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIEditSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/some-id/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIEditPolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/policies/some-id/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDeleteSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/some-id/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDeletePolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/policies/some-id/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIAuditLogPage(t *testing.T) {
	env := setup(t)
	env.audit.CreateEntry("secret.create", "admin", "user@test.com", "secret", "abc123", `{"key":"API_KEY"}`)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/audit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "secret.create")
	assert.Contains(t, rr.Body.String(), "user@test.com")
}

func TestUIAuditLogPageEmpty(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/audit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "No audit log entries yet.")
}

func TestUIAuditLogDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/audit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
