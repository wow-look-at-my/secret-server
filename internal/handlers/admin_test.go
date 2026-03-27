package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestAdminCreateAndDeleteSecret(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"key":"API_KEY","value":"secret","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	req = httptest.NewRequest("DELETE", "/admin/v1/secrets/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminCreateSecretMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"key":"API_KEY"}`
	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminUpdateSecret(t *testing.T) {
	env := setup(t)
	s, _ := env.db.CreateSecret("KEY", "old", "app", "prod")

	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"key":"KEY","value":"new","project":"app","environment":"prod"}`
	req := httptest.NewRequest("PUT", "/admin/v1/secrets/"+s.ID, strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	got, _ := env.db.GetSecret(s.ID)
	assert.Equal(t, "new", got.Value)
}

func TestAdminPolicyCRUD(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"name":"test","repository_pattern":"org/*","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	body = `{"name":"updated","repository_pattern":"org/*","ref_pattern":"*","project":"app","environment":"staging"}`
	req = httptest.NewRequest("PUT", "/admin/v1/policies/"+id, strings.NewReader(body))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	req = httptest.NewRequest("DELETE", "/admin/v1/policies/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAdminCreatePolicyMissingFields(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"name":"test"}`
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminCreatePolicyDefaultRefPattern(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"name":"test","repository_pattern":"org/*","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	policies, _ := env.db.ListPolicies()
	assert.Equal(t, "*", policies[0].RefPattern)
}

func TestAdminInvalidJSON(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader("not json"))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = httptest.NewRequest("PUT", "/admin/v1/secrets/someid", strings.NewReader("not json"))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	req = httptest.NewRequest("PUT", "/admin/v1/policies/someid", strings.NewReader("not json"))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
