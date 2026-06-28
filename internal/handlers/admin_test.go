package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validID returns a syntactically-valid UUID; used in test URLs where we
// just need something that passes validUUID but doesn't match any real row.
func validID() string {
	return uuid.New().String()
}

func TestAdminCreateAndDeleteGroup(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"kind":"group","name":"myapp"}`
	req := jsonReq("POST", "/admin/v1/nodes", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]
	require.NotEmpty(t, id)

	entries, err := env.audit.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "node.create", entries[0].Action)
	assert.Equal(t, "node", entries[0].ResourceType)

	req = httptest.NewRequest("DELETE", "/admin/v1/nodes/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminCreateSecret(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"kind":"secret","name":"API_KEY","value":"xyz"}`
	req := jsonReq("POST", "/admin/v1/nodes", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	// Verify the secret is readable.
	s, err := env.db.GetSecret(id)
	require.Nil(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "xyz", s.Value)
}

func TestAdminCreateNodeMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// No name.
	req := jsonReq("POST", "/admin/v1/nodes", `{"kind":"secret"}`)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Secret without value.
	req = jsonReq("POST", "/admin/v1/nodes", `{"kind":"secret","name":"X"}`)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Invalid kind.
	req = jsonReq("POST", "/admin/v1/nodes", `{"kind":"nonsense","name":"X"}`)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreateSecretUnderGroup(t *testing.T) {
	env := setup(t)
	g, err := env.db.CreateGroup(nil, "group")
	require.Nil(t, err)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"kind":"secret","name":"CHILD","value":"v","parent_id":"` + g.ID() + `"}`
	req := jsonReq("POST", "/admin/v1/nodes", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	s, err := env.db.GetSecret(created["id"])
	require.Nil(t, err)
	require.NotNil(t, s.ParentID())
	assert.Equal(t, g.ID(), *s.ParentID())
}

func TestAdminUpdateNodeRenameAndValue(t *testing.T) {
	env := setup(t)
	s, err := env.db.CreateSecret(nil, "OLD", "old-val")
	require.Nil(t, err)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"NEW","value":"new-val"}`
	req := jsonReq("PUT", "/admin/v1/nodes/"+s.ID(), body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetSecret(s.ID())
	assert.Equal(t, "NEW", got.Name())
	assert.Equal(t, "new-val", got.Value)
}

func TestAdminDeleteNonexistentNode(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/nodes/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminGetNode(t *testing.T) {
	env := setup(t)
	g, err := env.db.CreateGroup(nil, "parent")
	require.Nil(t, err)
	gID := g.ID()
	_, err = env.db.CreateSecret(&gID, "CHILD", "v")
	require.Nil(t, err)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes/"+gID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "parent", got["name"])
	assert.Equal(t, "group", got["kind"])
	children, _ := got["children"].([]any)
	require.Equal(t, 1, len(children))
}

func TestAdminListRootNodes(t *testing.T) {
	env := setup(t)
	env.db.CreateGroup(nil, "root1")
	env.db.CreateSecret(nil, "loose-secret", "v")

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var nodes []map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &nodes))
	require.Equal(t, 2, len(nodes))
}

// --- Policies ---

func TestAdminPolicyCRUD(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_patterns":["org/*"]}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	entries, _ := env.audit.ListEntries(10, 0)
	require.Equal(t, 1, len(entries))
	assert.Equal(t, "policy.create", entries[0].Action)

	body = `{"name":"updated","repository_patterns":["org/*"],"ref_patterns":["*"]}`
	req = jsonReq("PUT", "/admin/v1/policies/"+id, body)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	req = httptest.NewRequest("DELETE", "/admin/v1/policies/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminCreatePolicyMissingName(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// Empty name is still rejected.
	body := `{"repository_patterns":["org/*"]}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreatePolicyEmptyRepoPatternsAllowed(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// A name-only body (no repository patterns) creates a fail-closed
	// placeholder policy that matches nothing until patterns are added.
	body := `{"name":"x"}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	policies, _ := env.db.ListPolicies()
	require.Equal(t, 1, len(policies))
	assert.Empty(t, policies[0].RepositoryPatterns)
}

func TestAdminCreatePolicyDefaultRefActor(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_patterns":["org/*"]}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	policies, _ := env.db.ListPolicies()
	require.Equal(t, 1, len(policies))
	assert.Equal(t, []string{"*"}, policies[0].RefPatterns)
	assert.Equal(t, []string{"*"}, policies[0].ActorPatterns)
}

func TestAdminCreatePolicyInvalidGlob(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"bad","repository_patterns":["org/["]}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid glob pattern")
}

// --- Attach/detach and precedence ---

func TestAdminAttachDetachPolicy(t *testing.T) {
	env := setup(t)
	g, err := env.db.CreateGroup(nil, "g")
	require.Nil(t, err)
	p, err := env.db.CreatePolicy("p", []string{"org/*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"policy_id":"` + p.ID + `"}`
	req := jsonReq("POST", "/admin/v1/nodes/"+g.ID()+"/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Detach.
	req = httptest.NewRequest("DELETE", "/admin/v1/nodes/"+g.ID()+"/policies/"+p.ID, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminAddRemovePrecedence(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	a, _ := env.db.CreatePolicy("a", []string{"*"}, []string{"*"}, []string{"*"})
	b, _ := env.db.CreatePolicy("b", []string{"*"}, []string{"*"}, []string{"*"})
	env.db.AttachPolicy(g.ID(), a.ID)
	env.db.AttachPolicy(g.ID(), b.ID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// Add edge a depends on b.
	body := `{"policy_id":"` + a.ID + `","depends_on_id":"` + b.ID + `"}`
	req := jsonReq("POST", "/admin/v1/nodes/"+g.ID()+"/precedence", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Adding the reverse edge (b depends on a) should be rejected.
	body = `{"policy_id":"` + b.ID + `","depends_on_id":"` + a.ID + `"}`
	req = jsonReq("POST", "/admin/v1/nodes/"+g.ID()+"/precedence", body)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Remove the original edge.
	body = `{"policy_id":"` + a.ID + `","depends_on_id":"` + b.ID + `"}`
	req = jsonReq("DELETE", "/admin/v1/nodes/"+g.ID()+"/precedence", body)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminListNodePolicies(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	env.db.AttachPolicy(g.ID(), p.ID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/nodes/"+g.ID()+"/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Policies   []map[string]any `json:"policies"`
		Precedence []map[string]any `json:"precedence"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, 1, len(got.Policies))
}

// --- Misc ---

func TestAdminInvalidJSON(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := jsonReq("POST", "/admin/v1/nodes", "not json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = jsonReq("POST", "/admin/v1/policies", "not json")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminRequiresJSONContentType(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// POST /nodes with no Content-Type.
	req := httptest.NewRequest("POST", "/admin/v1/nodes", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code)
}

func TestAdminCreatePolicyDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"test","repository_patterns":["org/*"]}`
	req := jsonReq("POST", "/admin/v1/policies", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAdminCreateNodeDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"kind":"group","name":"x"}`
	req := jsonReq("POST", "/admin/v1/nodes", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
