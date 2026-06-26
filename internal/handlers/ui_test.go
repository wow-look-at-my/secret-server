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

func TestUIPages(t *testing.T) {
	env := setup(t)
	_, err := env.db.CreateSecret(nil, "KEY", "val")
	require.Nil(t, err)
	_, err = env.db.CreatePolicy("p", []string{"org/*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)

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
		{"GET", "/admin/secrets/new", http.StatusOK},
		{"GET", "/admin/secrets/new?kind=group", http.StatusOK},
		{"GET", "/admin/policies", http.StatusOK},
		{"GET", "/admin/policies/new", http.StatusOK},
		{"GET", "/admin/audit", http.StatusOK},
	}
	for _, p := range pages {
		req := httptest.NewRequest(p.method, p.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(t, p.status, rr.Code, "page %s", p.path)
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

func TestUICreateSecretForm(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "kind=secret&name=MY_KEY&value=my_secret"
	req := httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestUICreateGroupForm(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "kind=group&name=myapp"
	req := httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestUIEditAndDeleteSecretForm(t *testing.T) {
	env := setup(t)
	s, err := env.db.CreateSecret(nil, "UPDATEME", "old")
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Edit form renders.
	req := httptest.NewRequest("GET", "/admin/secrets/"+s.ID()+"/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// View a single node.
	req = httptest.NewRequest("GET", "/admin/secrets/"+s.ID(), nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Rename + change value via form.
	form := "name=RENAMED&value=new-value"
	req = httptest.NewRequest("POST", "/admin/secrets/"+s.ID(), strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)
	got, _ := env.db.GetSecret(s.ID())
	assert.Equal(t, "RENAMED", got.Name())
	assert.Equal(t, "new-value", got.Value)

	// Delete via form.
	req = httptest.NewRequest("POST", "/admin/secrets/"+s.ID()+"/delete", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ = env.db.GetSecret(s.ID())
	assert.Nil(t, got)
}

func TestUIAttachDetachPolicyForm(t *testing.T) {
	env := setup(t)
	s, err := env.db.CreateSecret(nil, "SECRET", "v")
	require.Nil(t, err)
	p, err := env.db.CreatePolicy("p", []string{"org/*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Attach.
	form := "policy_id=" + p.ID
	req := httptest.NewRequest("POST", "/admin/secrets/"+s.ID()+"/policies/attach", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	attached, _ := env.db.ListNodePolicies(s.ID())
	require.Equal(t, 1, len(attached))

	// Detach.
	req = httptest.NewRequest("POST", "/admin/secrets/"+s.ID()+"/policies/"+p.ID+"/detach", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	attached, _ = env.db.ListNodePolicies(s.ID())
	assert.Equal(t, 0, len(attached))
}

func TestUIPolicyCreateAndDelete(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Create via form.
	form := "name=test&repository_patterns=org/*&ref_patterns=*&actor_patterns=*"
	req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	policies, _ := env.db.ListPolicies()
	require.Equal(t, 1, len(policies))
	p := policies[0]

	// Edit form renders.
	req = httptest.NewRequest("GET", "/admin/policies/"+p.ID+"/edit", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Update via form.
	form = "name=updated&repository_patterns=org/new&ref_patterns=*&actor_patterns=*"
	req = httptest.NewRequest("POST", "/admin/policies/"+p.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetPolicy(p.ID)
	assert.Equal(t, "updated", got.Name)
	assert.Equal(t, []string{"org/new"}, got.RepositoryPatterns)

	// Delete via form.
	req = httptest.NewRequest("POST", "/admin/policies/"+p.ID+"/delete", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	policies, _ = env.db.ListPolicies()
	assert.Equal(t, 0, len(policies))
}

func TestUICreatePolicyMissingRepoPatterns(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=test&repository_patterns=&ref_patterns=*"
	req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	// Error is shown inline in the rendered form, not a status code change.
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "at least one repository pattern")
}

func TestUICatchAllRedirects(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/unknown-path", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/admin/", rr.Header().Get("Location"))
}

func TestUIParsePatternLines(t *testing.T) {
	// Unit test for the helper.
	got := parsePatternLines("a\nb\n\n  c  \nd")
	assert.Equal(t, []string{"a", "b", "c", "d"}, got)

	assert.Nil(t, parsePatternLines(""))
	assert.Nil(t, parsePatternLines("\n\n"))
}
