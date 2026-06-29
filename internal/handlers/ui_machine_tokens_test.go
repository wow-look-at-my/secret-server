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

func TestUIMachineTokenPages(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	for _, path := range []string{"/admin/machine-tokens", "/admin/machine-tokens/new"} {
		req := httptest.NewRequest("GET", path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "GET %s", path)
	}
}

func TestUIMachineTokenCreateAndDelete(t *testing.T) {
	env := setup(t)
	s, err := env.db.CreateSecret(nil, "API_KEY", "v")
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=reconcile&node_ids=" + s.ID()
	req := httptest.NewRequest("POST", "/admin/machine-tokens", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	// Success renders the show-once page (not a redirect) with the token visible.
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "sst_")

	tokens, err := env.db.ListMachineTokens()
	require.NoError(t, err)
	require.Equal(t, 1, len(tokens))
	id := tokens[0].ID

	req = httptest.NewRequest("GET", "/admin/machine-tokens", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "reconcile")

	req = httptest.NewRequest("POST", "/admin/machine-tokens/"+id+"/delete", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	tokens, _ = env.db.ListMachineTokens()
	assert.Equal(t, 0, len(tokens))
}

func TestUIMachineTokenCreateValidation(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret(nil, "S", "v")
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Missing name re-renders the form with an error, creating nothing.
	req := httptest.NewRequest("POST", "/admin/machine-tokens", strings.NewReader("node_ids="+s.ID()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Name is required")

	// No secret selected re-renders with an error.
	req = httptest.NewRequest("POST", "/admin/machine-tokens", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "at least one secret")

	tokens, _ := env.db.ListMachineTokens()
	assert.Equal(t, 0, len(tokens))
}

func TestUIMachineTokenEditAndUpdate(t *testing.T) {
	env := setup(t)
	a, _ := env.db.CreateSecret(nil, "A", "1")
	b, _ := env.db.CreateSecret(nil, "B", "2")
	_, rec, err := env.db.CreateMachineToken("t", []string{a.ID()})
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Edit form loads and pre-checks the currently-attached node.
	req := httptest.NewRequest("GET", "/admin/machine-tokens/"+rec.ID+"/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), a.ID())

	// Update to grant B instead of A.
	req = httptest.NewRequest("POST", "/admin/machine-tokens/"+rec.ID, strings.NewReader("node_ids="+b.ID()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusSeeOther, rr.Code)

	nodes, err := env.db.ListTokenNodes(rec.ID)
	require.Nil(t, err)
	require.Equal(t, 1, len(nodes))
	assert.Equal(t, "B", nodes[0].Name)
}

func TestUIMachineTokenUpdateRequiresASecret(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret(nil, "S", "v")
	_, rec, err := env.db.CreateMachineToken("t", []string{s.ID()})
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Posting no nodes re-renders the form with an error and leaves the grant.
	req := httptest.NewRequest("POST", "/admin/machine-tokens/"+rec.ID, strings.NewReader("name=t"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "at least one secret")

	nodes, _ := env.db.ListTokenNodes(rec.ID)
	assert.Equal(t, 1, len(nodes), "the prior grant is untouched")
}

func TestUIEditNonexistentMachineToken(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/machine-tokens/00000000-0000-0000-0000-000000000000/edit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIDeleteNonexistentMachineToken(t *testing.T) {
	env := setup(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/machine-tokens/00000000-0000-0000-0000-000000000000/delete", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUIListMachineTokensDBError(t *testing.T) {
	env := setupClosedMainDB(t)
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	req := httptest.NewRequest("GET", "/admin/machine-tokens", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
