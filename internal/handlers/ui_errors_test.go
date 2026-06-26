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

// Error-path coverage for the UI handlers. These exercise DB failures,
// nonexistent IDs, and malformed-form inputs so the defensive branches
// don't sit uncovered.

func TestUIDashboardDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIBrowseTreeDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIListPoliciesDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUINewNodeFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/new", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIEditNodeFormInvalidID(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/not-a-uuid/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIEditNodeFormNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/"+validID()+"/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIDeleteNodeFormInvalidID(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/not-a-uuid/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIDeleteNodeFormNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/"+validID()+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIUpdateNodeFormInvalidID(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/not-a-uuid", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIUpdateNodeFormRenameNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/"+validID(),
		strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIAttachPolicyFormInvalidIDs(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Invalid node ID.
	req := httptest.NewRequest("POST", "/admin/secrets/not-a-uuid/policies/attach",
		strings.NewReader("policy_id="+validID()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Valid node ID + invalid policy ID.
	g, _ := env.db.CreateGroup(nil, "g")
	req = httptest.NewRequest("POST", "/admin/secrets/"+g.ID()+"/policies/attach",
		strings.NewReader("policy_id=not-a-uuid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestUIDetachPolicyFormInvalidIDs(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/not-a-uuid/policies/"+validID()+"/detach", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIDetachPolicyFormNotAttached(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// p is not attached to g; detach returns 404.
	req := httptest.NewRequest("POST", "/admin/secrets/"+g.ID()+"/policies/"+p.ID+"/detach", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIEditPolicyNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/policies/"+validID()+"/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIUpdatePolicyNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=x&repository_patterns=org/*&ref_patterns=*&actor_patterns=*"
	req := httptest.NewRequest("POST", "/admin/policies/"+validID(), strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIUpdatePolicyInvalidPatterns(t *testing.T) {
	env := setup(t)
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=x&repository_patterns=&ref_patterns=*&actor_patterns=*"
	req := httptest.NewRequest("POST", "/admin/policies/"+p.ID, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "at least one repository pattern")
}

func TestUIDeletePolicyNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/policies/"+validID()+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestUIAuditLog exercises the audit log page with entries.
func TestUIAuditLog(t *testing.T) {
	env := setup(t)
	env.audit.CreateEntry("node.create", "admin", "test", "node", "id", "{}")
	env.audit.CreateEntry("policy.create", "admin", "test", "policy", "id", "{}")

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/audit?page=1", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUIAuditLogDBError(t *testing.T) {
	env := setup(t)
	env.audit.Close()
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/audit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestUICreateNodeFormDBError covers the DB-failure path during create.
func TestUICreateNodeFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Create a group via the form; DB is closed so it'll fail and the
	// template re-renders with an error. But loadGroupList also fails,
	// so we get a 500 instead.
	form := "kind=group&name=x"
	req := httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	// Either 200 (re-rendered with error) or 500 (load failed) — both are
	// valid error paths. We just need it to not be a 303 redirect.
	require.NotEqual(t, http.StatusSeeOther, rr.Code)
}
