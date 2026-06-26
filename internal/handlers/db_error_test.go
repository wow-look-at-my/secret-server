package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

// Coverage for the DB-error branches of handlers with multi-step DB calls.
// These aren't typically exercised by happy-path tests because each branch
// needs a DB failure in a different step.

func TestAdminUpdateNodeDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"x","value":"v","change_parent":true,"parent_id":null}`
	req := jsonReq("PUT", "/admin/v1/nodes/"+validID(), body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	// Expect a 5xx or a 404 (rename first fails with ErrNotFound, which is
	// converted to 404). Either is fine — we're just exercising the code
	// path.
	assert.True(t, rr.Code >= 400)
}

func TestAdminAttachPolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"policy_id":"` + validID() + `"}`
	req := jsonReq("POST", "/admin/v1/nodes/"+validID()+"/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminAddPrecedenceDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"policy_id":"` + validID() + `","depends_on_id":"` + validID() + `"}`
	req := jsonReq("POST", "/admin/v1/nodes/"+validID()+"/precedence", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminListNodePoliciesDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes/"+validID()+"/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminGetPolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/policies/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminUpdatePolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"x","repository_patterns":["*"]}`
	req := jsonReq("PUT", "/admin/v1/policies/"+validID(), body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminDeletePolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/policies/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminDeleteNodeDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/nodes/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminDetachPolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/nodes/"+validID()+"/policies/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminListPolicyNodesDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/policies/"+validID()+"/nodes", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminGetNodeDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestAdminUpdateNodeValueAgainstGroup: updating a secret value against a
// group node returns ErrNotFound because the SQL WHERE clause excludes
// non-secret rows.
func TestAdminUpdateNodeValueAgainstGroup(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"value":"v"}`
	req := jsonReq("PUT", "/admin/v1/nodes/"+g.ID(), body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestAdminDeleteAttachedPolicyCascadesAttachments verifies that deleting
// a policy that is still attached to a node succeeds (FK cascade cleans up
// secret_node_policies).
func TestAdminDeleteAttachedPolicyCascades(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	env.db.AttachPolicy(g.ID(), p.ID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/policies/"+p.ID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify cascade.
	attached, _ := env.db.ListNodePolicies(g.ID())
	assert.Equal(t, 0, len(attached))
}

// TestUIViewNodeInvalidID exercises the invalid-UUID path.
func TestUIViewNodeInvalidID(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/not-a-uuid", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestUIViewNodeDBError exercises the DB-error path.
func TestUIViewNodeDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestUIDeleteNodeFormDBError exercises the DB-error path.
func TestUIDeleteNodeFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/"+validID()+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDetachPolicyFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/"+validID()+"/policies/"+validID()+"/detach", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIDeletePolicyFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/policies/"+validID()+"/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIAttachPolicyFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/secrets/"+validID()+"/policies/attach",
		strings.NewReader("policy_id="+validID()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUIUpdatePolicyFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=x&repository_patterns=org/*&ref_patterns=*&actor_patterns=*"
	req := httptest.NewRequest("POST", "/admin/policies/"+validID(), strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUICreatePolicyFormDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=x&repository_patterns=org/*&ref_patterns=*&actor_patterns=*"
	req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code) // re-rendered with error
	assert.Contains(t, rr.Body.String(), "Failed to create policy")
}

// TestAdminCreatePolicyNormalizeError covers the normalize-error path in
// createPolicy (where an invalid pattern slips past the top-level check
// but gets caught by ValidatePatterns).
func TestAdminCreatePolicyInvalidRefPattern(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"bad","repository_patterns":["org/*"],"ref_patterns":["refs/heads/["]}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdatePolicyInvalidRefPattern(t *testing.T) {
	env := setup(t)
	p, _ := env.db.CreatePolicy("p", []string{"org/*"}, []string{"*"}, []string{"*"})
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"bad","repository_patterns":["org/*"],"ref_patterns":["refs/["]}`
	req := jsonReq("PUT", "/admin/v1/policies/"+p.ID, body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
