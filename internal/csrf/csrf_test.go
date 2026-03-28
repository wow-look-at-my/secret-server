package csrf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wow-look-at-my/testify/assert"
)

func TestProtect_GETSetsToken(t *testing.T) {
	handler := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := TokenFromContext(r.Context())
		assert.NotEmpty(t, token)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/form", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	cookies := rr.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == cookieName {
			found = true
			assert.NotEmpty(t, c.Value)
		}
	}
	assert.True(t, found, "csrf cookie should be set")
}

func TestProtect_POSTWithoutCookie(t *testing.T) {
	handler := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/submit", strings.NewReader("csrf_token=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestProtect_POSTWithMismatch(t *testing.T) {
	handler := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/submit", strings.NewReader("csrf_token=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "correct"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestProtect_POSTWithValidToken(t *testing.T) {
	handler := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := "validtoken123"
	req := httptest.NewRequest("POST", "/submit", strings.NewReader("csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestProtect_GETReusesCookie(t *testing.T) {
	handler := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := TokenFromContext(r.Context())
		assert.Equal(t, "existing", token)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/form", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "existing"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Should not set a new cookie since one already exists
	for _, c := range rr.Result().Cookies() {
		assert.NotEqual(t, cookieName, c.Name, "should not re-set existing cookie")
	}
}
