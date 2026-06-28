package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminListPolicies exercises the GET /admin/v1/policies endpoint.
func TestAdminListPolicies(t *testing.T) {
	env := setup(t)
	env.db.CreatePolicy("p1", []string{"*"}, []string{"*"}, []string{"*"})
	env.db.CreatePolicy("p2", []string{"*"}, []string{"*"}, []string{"*"})

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var policies []map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &policies))
	assert.Equal(t, 2, len(policies))
}

// TestAdminDeleteGroup cascades children and policy attachments.
func TestAdminDeleteGroup(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "to-delete")
	gID := g.ID()
	env.db.CreateSecret(&gID, "LEAF", "v")

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/nodes/"+gID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

// TestAdminUpdateNodeAllFields exercises rename + value + move in one call.
func TestAdminUpdateNodeAllFields(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	s, _ := env.db.CreateSecret(nil, "S", "v")

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"RENAMED","value":"new","parent_id":"` + g.ID() + `","change_parent":true}`
	req := jsonReq("PUT", "/admin/v1/nodes/"+s.ID(), body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetSecret(s.ID())
	assert.Equal(t, "RENAMED", got.Name())
	assert.Equal(t, "new", got.Value)
	require.NotNil(t, got.ParentID())
	assert.Equal(t, g.ID(), *got.ParentID())
}

func TestAdminUpdateNodeInvalidID(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"x"}`
	req := jsonReq("PUT", "/admin/v1/nodes/not-a-uuid", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminDeleteNodeInvalidID(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/nodes/not-a-uuid", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminGetNodeNotFound(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminGetNodeInvalidID(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes/not-a-uuid", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestAdminAttachPolicyInvalidIDs covers validation branches.
func TestAdminAttachPolicyInvalidIDs(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// Invalid node ID in URL.
	req := jsonReq("POST", "/admin/v1/nodes/not-a-uuid/policies", `{"policy_id":"`+validID()+`"}`)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Valid node ID but invalid policy ID in body.
	req = jsonReq("POST", "/admin/v1/nodes/"+validID()+"/policies", `{"policy_id":"not-a-uuid"}`)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestAdminAddPrecedenceInvalidIDs exercises validation branches.
func TestAdminAddPrecedenceInvalidIDs(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// Invalid node ID.
	req := jsonReq("POST", "/admin/v1/nodes/not-a-uuid/precedence",
		`{"policy_id":"`+validID()+`","depends_on_id":"`+validID()+`"}`)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Invalid policy/depends UUIDs.
	req = jsonReq("POST", "/admin/v1/nodes/"+validID()+"/precedence",
		`{"policy_id":"not","depends_on_id":"not"}`)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminDetachPolicyInvalidIDs(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/nodes/not-a-uuid/policies/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminRemovePrecedenceInvalidID(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := jsonReq("DELETE", "/admin/v1/nodes/not-a-uuid/precedence",
		`{"policy_id":"`+validID()+`","depends_on_id":"`+validID()+`"}`)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestAdminListRootNodesDBError covers the DB-error path.
func TestAdminListRootNodesDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminListPoliciesDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
