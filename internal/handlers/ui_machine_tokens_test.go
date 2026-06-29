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
	p, err := env.db.CreatePolicy("hookpol", []string{"*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)

	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	form := "name=reconcile&policy_id=" + p.ID
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
	p, _ := env.db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	h := NewUIHandler(env.db, env.audit, env.tmpl)
	mux := chi.NewRouter()
	h.Register(mux)

	// Missing name re-renders the form with an error, creating nothing.
	req := httptest.NewRequest("POST", "/admin/machine-tokens", strings.NewReader("policy_id="+p.ID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Name is required")

	// Unknown policy re-renders the form with an error.
	req = httptest.NewRequest("POST", "/admin/machine-tokens", strings.NewReader("name=x&policy_id=00000000-0000-0000-0000-000000000000"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "valid policy")

	tokens, _ := env.db.ListMachineTokens()
	assert.Equal(t, 0, len(tokens))
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
