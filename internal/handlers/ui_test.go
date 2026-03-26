package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestUIPages(t *testing.T) {
	env := setup(t)
	env.db.CreateSecret("KEY", "val", "app", "prod")
	env.db.CreatePolicy("p", "org/*", "*", "app", "prod")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	pages := []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/ui/", http.StatusOK},
		{"GET", "/ui/secrets", http.StatusOK},
		{"GET", "/ui/secrets?project=app", http.StatusOK},
		{"GET", "/ui/secrets/new", http.StatusOK},
		{"GET", "/ui/policies", http.StatusOK},
		{"GET", "/ui/policies/new", http.StatusOK},
	}

	for _, p := range pages {
		req := httptest.NewRequest(p.method, p.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(t, p.status, rr.Code)
	}
}

func TestUISecretCreateEditDelete(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "key=MY_KEY&value=my_secret&project=testproj&environment=staging"
	req := httptest.NewRequest("POST", "/ui/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	secrets, _ := env.db.ListSecrets("testproj", "staging")
	require.Equal(t, 1, len(secrets))
	id := secrets[0].ID

	req = httptest.NewRequest("GET", "/ui/secrets/"+id+"/edit", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	form = "key=MY_KEY&value=updated_secret&project=testproj&environment=staging"
	req = httptest.NewRequest("POST", "/ui/secrets/"+id, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(id)
	assert.Equal(t, "updated_secret", got.Value)

	req = httptest.NewRequest("POST", "/ui/secrets/"+id+"/delete", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ = env.db.GetSecret(id)
	assert.Nil(t, got)
}

func TestUIPolicyCreateEditDelete(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "name=Test+Policy&repository_pattern=org/*&ref_pattern=*&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	policies, _ := env.db.ListPolicies()
	require.Equal(t, 1, len(policies))
	id := policies[0].ID

	req = httptest.NewRequest("GET", "/ui/policies/"+id+"/edit", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	form = "name=Updated+Policy&repository_pattern=org/*&ref_pattern=refs/heads/main&project=app&environment=staging"
	req = httptest.NewRequest("POST", "/ui/policies/"+id, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(id)
	assert.Equal(t, "Updated Policy", got.Name)
	assert.Equal(t, "staging", got.Environment)

	req = httptest.NewRequest("POST", "/ui/policies/"+id+"/delete", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ = env.db.GetPolicy(id)
	assert.Nil(t, got)
}

func TestUIEditSecretNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/secrets/nonexistent/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIEditPolicyNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/policies/nonexistent/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIPolicyCreateDefaultRefPattern(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "name=NoRef&repository_pattern=org/*&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/policies", strings.NewReader(form))
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
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/something-else", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/ui/", rr.Header().Get("Location"))
}

func TestUISecretCreateDuplicate(t *testing.T) {
	env := setup(t)
	env.db.CreateSecret("DUP_KEY", "val", "proj", "env")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "key=DUP_KEY&value=val2&project=proj&environment=env"
	req := httptest.NewRequest("POST", "/ui/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUIListSecretsWithEnvFilter(t *testing.T) {
	env := setup(t)
	env.db.CreateSecret("K1", "v1", "proj", "prod")
	env.db.CreateSecret("K2", "v2", "proj", "dev")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/secrets?project=proj&environment=prod", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "K1")
}

func TestUIUpdatePolicyViaForm(t *testing.T) {
	env := setup(t)
	p, _ := env.db.CreatePolicy("test", "org/*", "*", "app", "prod")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "name=Updated&repository_pattern=org/*&ref_pattern=refs/heads/main&project=app&environment=staging"
	req := httptest.NewRequest("POST", "/ui/policies/"+p.ID, strings.NewReader(form))
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
	p, _ := env.db.CreatePolicy("test", "org/*", "refs/heads/main", "app", "prod")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "name=Updated&repository_pattern=org/*&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/policies/"+p.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(p.ID)
	assert.Equal(t, "*", got.RefPattern)
}

func TestUIDeleteSecretViaForm(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret("DEL", "val", "app", "prod")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/ui/secrets/"+s.ID+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Nil(t, got)
}

func TestUIDeletePolicyViaForm(t *testing.T) {
	env := setup(t)
	p, _ := env.db.CreatePolicy("del", "org/*", "*", "app", "prod")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/ui/policies/"+p.ID+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(p.ID)
	assert.Nil(t, got)
}

func TestUIUpdateSecretViaForm(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret("UPD", "old", "app", "prod")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "key=UPD&value=new_val&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/secrets/"+s.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Equal(t, "new_val", got.Value)
}

// DB error tests use a closed database to trigger error paths.

func TestUICreateSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "key=K&value=v&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUIUpdateSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "key=K&value=v&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/secrets/some-id", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUICreatePolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "name=P&repository_pattern=org/*&ref_pattern=*&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUIUpdatePolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	form := "name=P&repository_pattern=org/*&ref_pattern=*&project=app&environment=prod"
	req := httptest.NewRequest("POST", "/ui/policies/some-id", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIListSecretsDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIListPoliciesDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDashboardDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIEditSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/secrets/some-id/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIEditPolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/ui/policies/some-id/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDeleteSecretDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/ui/secrets/some-id/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDeletePolicyDBError(t *testing.T) {
	env := setupClosedDB(t)
	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/ui/policies/some-id/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
