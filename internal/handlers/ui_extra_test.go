package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUIViewNode exercises the single-node view page, which walks the
// breadcrumb chain, computes effective policies from ancestors, and renders
// the attach-policy form.
func TestUIViewNode(t *testing.T) {
	env := setup(t)

	// Tree: root -> mid -> leaf. Attach policy to root so the leaf's
	// effective policy set is non-empty via inheritance.
	root, _ := env.db.CreateGroup(nil, "root")
	rootID := root.ID()
	mid, _ := env.db.CreateGroup(&rootID, "mid")
	midID := mid.ID()
	leaf, _ := env.db.CreateSecret(&midID, "LEAF", "value")
	p, _ := env.db.CreatePolicy("p", []string{"org/*"}, []string{"*"}, []string{"*"})
	require.Nil(t, env.db.AttachPolicy(rootID, p.ID))

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// View the leaf.
	req := httptest.NewRequest("GET", "/admin/secrets/"+leaf.ID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "LEAF")
	assert.Contains(t, body, "root")
	assert.Contains(t, body, "mid")
	// Attach form should list the policy as available on the leaf (not yet
	// attached there) — but actually p is attached to root, not leaf, so
	// from leaf's perspective it's still "not attached here" and appears
	// in AvailablePolicies.
	assert.Contains(t, body, "Attach a policy")

	// View the root to exercise a group-with-children render.
	req = httptest.NewRequest("GET", "/admin/secrets/"+rootID, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
}

// TestUIViewNodeMachineTokenBadge: a secret granted ONLY by a directly-attached
// machine token shows the MACHINE TOKEN badge and NOT the "no policies" badge.
func TestUIViewNodeMachineTokenBadge(t *testing.T) {
	env := setup(t)

	// A group so the secret renders inside the tree (the badge lives on the
	// tree row, not the page header). Attach the token directly to the leaf.
	g, _ := env.db.CreateGroup(nil, "grp")
	gid := g.ID()
	leaf, _ := env.db.CreateSecret(&gid, "TOKEN_ONLY", "v")
	_, _, err := env.db.CreateMachineToken("t", nil, []string{leaf.ID()})
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// View the group so its child (the leaf) is rendered in the node tree.
	req := httptest.NewRequest("GET", "/admin/secrets/"+gid, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "node-machine-token", "machine-token badge is rendered")
	assert.Contains(t, body, "machine token")
	assert.NotContains(t, body, "No policies attached at this node or any ancestor",
		"the no-policies warning is suppressed for a machine-token-granted node")
}

// TestUIViewNodeNoPoliciesBadge: a node granted by neither a policy nor a
// machine token still shows the "no policies" warning and no machine-token badge.
func TestUIViewNodeNoPoliciesBadge(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "grp")
	gid := g.ID()
	_, _ = env.db.CreateSecret(&gid, "UNREACHABLE", "v")

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/"+gid, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "No policies attached at this node or any ancestor",
		"a node with no policy and no token shows the no-policies warning")
	assert.NotContains(t, body, "node-machine-token")
}

// TestUIViewNodeMachineTokenViaBoundPolicyInherits: a leaf reached only because
// a machine token's bound policy is attached to an ancestor group gets the badge
// (inheritance mirrors the effective-policy walk) and loses the warning.
func TestUIViewNodeMachineTokenViaBoundPolicyInherits(t *testing.T) {
	env := setup(t)

	root, _ := env.db.CreateGroup(nil, "root")
	rootID := root.ID()
	leaf, _ := env.db.CreateSecret(&rootID, "INHERITED", "v")

	// Bind a policy to a token and attach that policy to the root group; the
	// leaf is reachable only via inheritance down from the group.
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	require.Nil(t, env.db.AttachPolicy(rootID, p.ID))
	_, _, err := env.db.CreateMachineToken("bound", &p.ID, nil)
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// View the leaf directly: the ancestor walk must surface the badge even
	// though the seed node (root) is outside the rendered subtree.
	req := httptest.NewRequest("GET", "/admin/secrets/"+leaf.ID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "A machine token grants access to this",
		"the leaf inherits machine-token access from its ancestor group")
	assert.NotContains(t, body, "no effective policies",
		"the no-effective-policies error is suppressed when a token grants it")
}

func TestUIViewNodeNotFound(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIBase64JSONDecode(t *testing.T) {
	// Unit test for the helper. Valid base64-encoded JSON — full decode, not
	// redacted, per master #57.
	plain := `{"user":"alice","count":42}`
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	got := base64JSONDecode(encoded)
	assert.Contains(t, got, `"user": "alice"`)
	assert.Contains(t, got, `"count": 42`)

	// URL-safe base64 also works.
	urlEnc := base64.URLEncoding.EncodeToString([]byte(plain))
	got = base64JSONDecode(urlEnc)
	assert.NotEqual(t, "", got)

	// Non-base64 gives empty.
	assert.Equal(t, "", base64JSONDecode("!!!"))

	// Base64-encoded but not a JSON object gives empty.
	notJSON := base64.StdEncoding.EncodeToString([]byte("not json"))
	assert.Equal(t, "", base64JSONDecode(notJSON))
}

func TestUIEditNodeFormSecret(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret(nil, "EDITABLE", "v")

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/"+s.ID()+"/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "EDITABLE")
}

func TestUIEditNodeFormGroup(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "editable-group")

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/"+g.ID()+"/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "editable-group")
}

func TestUIEditNodeFormWithJSONValue(t *testing.T) {
	// When the value is base64-encoded JSON, the edit form shows a
	// structure hint. Exercises the JSONStructure code path.
	env := setup(t)
	plain := `{"key":"value"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	s, _ := env.db.CreateSecret(nil, "JSON_SECRET", encoded)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/secrets/"+s.ID()+"/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Base64-encoded JSON detected")
}

// TestUIUpdateNodeFormMove exercises the move-parent code path on the
// update handler.
func TestUIUpdateNodeFormMove(t *testing.T) {
	env := setup(t)
	g1, _ := env.db.CreateGroup(nil, "g1")
	g2, _ := env.db.CreateGroup(nil, "g2")
	g1ID := g1.ID()
	s, _ := env.db.CreateSecret(&g1ID, "MOVABLE", "v")

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "move=1&parent_id=" + g2.ID()
	req := httptest.NewRequest("POST", "/admin/secrets/"+s.ID(), strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(s.ID())
	require.NotNil(t, got.ParentID())
	assert.Equal(t, g2.ID(), *got.ParentID())
}

// TestUIUpdateNodeFormMoveToRoot exercises moving a node back to the root.
func TestUIUpdateNodeFormMoveToRoot(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	gID := g.ID()
	s, _ := env.db.CreateSecret(&gID, "MOVABLE", "v")

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "move=1&parent_id="
	req := httptest.NewRequest("POST", "/admin/secrets/"+s.ID(), strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	got, _ := env.db.GetSecret(s.ID())
	assert.Nil(t, got.ParentID())
}

func TestUICreateNodeFormValidation(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Missing name.
	form := "kind=secret&value=v"
	req := httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code) // Re-renders form with error
	assert.Contains(t, rr.Body.String(), "Name is required")

	// Secret without value.
	form = "kind=secret&name=X"
	req = httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Value is required")

	// Invalid kind.
	form = "kind=nonsense&name=X"
	req = httptest.NewRequest("POST", "/admin/secrets", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestUIListPoliciesWithAttachedNodes exercises the CountNodesReferencingPolicy
// path in listPolicies.
func TestUIListPoliciesWithAttachedNodes(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	p, _ := env.db.CreatePolicy("p", []string{"org/*"}, []string{"*"}, []string{"*"})
	env.db.AttachPolicy(g.ID(), p.ID)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "1 node(s)")
}

// TestAdminListPolicyNodes exercises the GET /admin/v1/policies/{id}/nodes
// backward-view endpoint.
func TestAdminListPolicyNodes(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "attached-group")
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	env.db.AttachPolicy(g.ID(), p.ID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/policies/"+p.ID+"/nodes", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var nodes []map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &nodes))
	require.Equal(t, 1, len(nodes))
	assert.Equal(t, "attached-group", nodes[0]["name"])
}

// TestAdminGetPolicy exercises the GET /admin/v1/policies/{id} endpoint.
func TestAdminGetPolicy(t *testing.T) {
	env := setup(t)
	p, _ := env.db.CreatePolicy("findme", []string{"org/*"}, []string{"*"}, []string{"*"})

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/v1/policies/"+p.ID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "findme", got["Name"])

	// Non-existent policy.
	req = httptest.NewRequest("GET", "/admin/v1/policies/"+validID(), nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestAdminUpdateNodeRenameNotFound covers the "rename nonexistent" path.
func TestAdminUpdateNodeRenameNotFound(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"new"}`
	req := jsonReq("PUT", "/admin/v1/nodes/"+validID(), body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestAdminDetachNonAttachedPolicy covers the ErrNotFound branch of detach.
func TestAdminDetachNonAttachedPolicy(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	// p is not attached to g; detach should 404.
	req := httptest.NewRequest("DELETE", "/admin/v1/nodes/"+g.ID()+"/policies/"+p.ID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestAdminDeleteNonexistentPolicy covers the not-found branch of delete.
func TestAdminDeleteNonexistentPolicy(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("DELETE", "/admin/v1/policies/"+validID(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestAdminUpdatePolicyNotFound covers the not-found branch of update.
func TestAdminUpdatePolicyNotFound(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"name":"new","repository_patterns":["*"]}`
	req := jsonReq("PUT", "/admin/v1/policies/"+validID(), body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestAdminRemovePrecedenceNotFound covers the not-found branch.
func TestAdminRemovePrecedenceNotFound(t *testing.T) {
	env := setup(t)
	g, _ := env.db.CreateGroup(nil, "g")
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	q, _ := env.db.CreatePolicy("q", []string{"*"}, []string{"*"}, []string{"*"})
	env.db.AttachPolicy(g.ID(), p.ID)
	env.db.AttachPolicy(g.ID(), q.ID)

	h := NewAdminHandler(env.db, env.audit)
	mux := chi.NewRouter()
	h.Register(mux)

	body := `{"policy_id":"` + p.ID + `","depends_on_id":"` + q.ID + `"}`
	req := jsonReq("DELETE", "/admin/v1/nodes/"+g.ID()+"/precedence", body)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}
