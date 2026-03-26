package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/templates"
)

type testEnv struct {
	db	*database.DB
	tmpl	*templates.Templates
	key	*rsa.PrivateKey
	jwk	jose.JSONWebKey
	pub	jose.JSONWebKey
	oidc	*auth.GitHubOIDCValidator
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	encKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(encKey)
	require.Nil(t, err)

	f, err := os.CreateTemp(t.TempDir(), "test-*.db")
	require.Nil(t, err)

	f.Close()
	db, err := database.New(f.Name(), enc)
	require.Nil(t, err)

	t.Cleanup(func() { db.Close() })

	tmpl, err := templates.New()
	require.Nil(t, err)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: rsaKey, KeyID: "test", Algorithm: "RS256"}
	pub := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "test", Algorithm: "RS256"}

	oidc := auth.NewGitHubOIDCValidator("https://secrets.example.com")
	auth.SetJWKSForTesting(oidc, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})

	return &testEnv{db: db, tmpl: tmpl, key: rsaKey, jwk: jwk, pub: pub, oidc: oidc}
}

func makeOIDCToken(t *testing.T, jwk jose.JSONWebKey, repo, ref string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	require.Nil(t, err)

	stdClaims := jwt.Claims{
		Issuer:		"https://token.actions.githubusercontent.com",
		Subject:	"repo:" + repo + ":ref:" + ref,
		Audience:	jwt.Audience{"https://secrets.example.com"},
		Expiry:		jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore:	jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:	jwt.NewNumericDate(time.Now()),
	}
	customClaims := map[string]string{
		"repository":		repo,
		"repository_owner":	strings.Split(repo, "/")[0],
		"ref":			ref,
	}
	token, err := jwt.Signed(signer).Claims(stdClaims).Claims(customClaims).Serialize()
	require.Nil(t, err)

	return token
}

func TestPublicFetchSecretsNoToken(t *testing.T) {
	env := setup(t)
	h := NewPublicHandler(env.db, env.oidc)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest("POST", "/public/v1/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

}

func TestPublicFetchSecretsWithPolicy(t *testing.T) {
	env := setup(t)

	// Create secret and policy
	env.db.CreateSecret("DB_URL", "postgres://localhost", "myapp", "prod")
	env.db.CreatePolicy("allow", "myorg/*", "*", "myapp", "prod")

	h := NewPublicHandler(env.db, env.oidc)
	mux := http.NewServeMux()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("POST", "/public/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var result map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))

	assert.Equal(t, "postgres://localhost", result["DB_URL"])

}

func TestPublicFetchSecretsNoMatchingPolicy(t *testing.T) {
	env := setup(t)
	env.db.CreateSecret("KEY", "val", "app", "prod")
	// Policy for different repo pattern
	env.db.CreatePolicy("other", "otherorg/*", "*", "app", "prod")

	h := NewPublicHandler(env.db, env.oidc)
	mux := http.NewServeMux()
	h.Register(mux)

	token := makeOIDCToken(t, env.jwk, "myorg/repo", "refs/heads/main")
	req := httptest.NewRequest("POST", "/public/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "{}", strings.TrimSpace(rr.Body.String()))

}

func TestAdminCreateAndDeleteSecret(t *testing.T) {
	env := setup(t)
	h := NewAdminHandler(env.db)
	mux := http.NewServeMux()
	h.Register(mux)

	// Create
	body := `{"key":"API_KEY","value":"secret","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	// Delete
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

	// Create
	body := `{"name":"test","repository_pattern":"org/*","project":"app","environment":"prod"}`
	req := httptest.NewRequest("POST", "/admin/v1/policies", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var created map[string]string
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["id"]

	// Update
	body = `{"name":"updated","repository_pattern":"org/*","ref_pattern":"*","project":"app","environment":"staging"}`
	req = httptest.NewRequest("PUT", "/admin/v1/policies/"+id, strings.NewReader(body))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Delete
	req = httptest.NewRequest("DELETE", "/admin/v1/policies/"+id, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

}

func TestUIPages(t *testing.T) {
	env := setup(t)
	env.db.CreateSecret("KEY", "val", "app", "prod")
	env.db.CreatePolicy("p", "org/*", "*", "app", "prod")

	h := NewUIHandler(env.db, env.tmpl)
	mux := http.NewServeMux()
	h.Register(mux)

	pages := []struct {
		method	string
		path	string
		status	int
	}{
		{"GET", "/ui/", http.StatusOK},
		{"GET", "/ui/secrets", http.StatusOK},
		{"GET", "/ui/secrets?project=app", http.StatusOK},
		{"GET", "/ui/secrets/new", http.StatusOK},
		{"GET", "/ui/policies", http.StatusOK},
		{"GET", "/ui/policies/new", http.StatusOK},
	}

	for _, p := range pages {
		req := httptest.NewRequest(p.method, p.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(t, p.status, rr.Code)

	}
}

// Unused import guard
var _ = context.Background
