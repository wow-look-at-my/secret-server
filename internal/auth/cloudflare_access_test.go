package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestRequireCFAccessNoToken(t *testing.T) {
	v := NewCloudflareAccessValidator("team", "aud")
	handler := v.RequireCFAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestValidateRequestFromHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "test-key", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
		w.Header().Set("Content-Type", "application/json")
		data, _ := keys.Key("test-key")[0].MarshalJSON()
		w.Write([]byte(`{"keys":[` + string(data) + `]}`))
	}))
	defer ts.Close()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	require.Nil(t, err)

	claims := jwt.Claims{
		Issuer:    "test",
		Audience:  jwt.Audience{"test-aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	customClaims := struct {
		Email string `json:"email"`
	}{Email: "admin@example.com"}
	token, err := jwt.Signed(signer).Claims(claims).Claims(customClaims).Serialize()
	require.Nil(t, err)

	v := NewCloudflareAccessValidator("team", "test-aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", token)

	identity, err := v.ValidateRequest(req)
	assert.Nil(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "admin@example.com", identity.Email)
}

func TestValidateRequestFromCookie(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "ck", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "ck", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	claims := jwt.Claims{
		Audience:  jwt.Audience{"aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token, _ := jwt.Signed(signer).Claims(claims).Serialize()

	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})

	identity, err := v.ValidateRequest(req)
	assert.Nil(t, err)
	require.NotNil(t, identity)
}

func TestValidateRequestExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "ek", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "ek", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	claims := jwt.Claims{
		Audience:  jwt.Audience{"aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
	}
	token, _ := jwt.Signed(signer).Claims(claims).Serialize()

	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", token)

	_, err := v.ValidateRequest(req)
	require.NotNil(t, err)
}

func TestValidateRequestWrongAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "wk", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "wk", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	claims := jwt.Claims{
		Audience:  jwt.Audience{"wrong-aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token, _ := jwt.Signed(signer).Claims(claims).Serialize()

	v := NewCloudflareAccessValidator("team", "correct-aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", token)

	_, err := v.ValidateRequest(req)
	require.NotNil(t, err)
}

func TestCFAccessGetKeysCached(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "cf-key", Algorithm: "RS256"}

	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	keys, err := v.getKeys(context.Background())
	require.Nil(t, err)
	require.Equal(t, 1, len(keys.Keys))
	assert.Equal(t, "cf-key", keys.Keys[0].KeyID)
}

func TestCFAccessGetKeysCacheExpiry(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	newPub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "new-key", Algorithm: "RS256"}

	// Serve fresh keys from a mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := newPub.MarshalJSON()
		w.Write([]byte(`{"keys":[` + string(data) + `]}`))
	}))
	defer ts.Close()

	// Use the mock server's host as the "team domain"
	// We need to override the URL construction. Since we can't easily do that,
	// we'll test that an expired cache with unreachable server returns error.
	v := NewCloudflareAccessValidator("localhost-nonexistent-domain-12345", "aud")
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	oldPub := jose.JSONWebKey{Key: &oldKey.PublicKey, KeyID: "old-key", Algorithm: "RS256"}
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{oldPub}}
	v.fetched = time.Now().Add(-2 * time.Hour) // expired

	// Context with short timeout to avoid hanging
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := v.getKeys(ctx)
	require.NotNil(t, err)
}

func TestRequireCFAccessMiddlewareWithValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "mw", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "mw", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	claims := jwt.Claims{
		Audience:  jwt.Audience{"aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token, _ := jwt.Signed(signer).Claims(claims).Serialize()

	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	called := false
	handler := v.RequireCFAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, called)
}

func TestValidateRequestInvalidJWT(t *testing.T) {
	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	v.fetched = time.Now()

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", "not-a-valid-jwt")

	_, err := v.ValidateRequest(req)
	require.NotNil(t, err)
}

func TestCFAccessGetKeysFromServer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "srv", Algorithm: "RS256"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := pubJWK.MarshalJSON()
		w.Write([]byte(`{"keys":[` + string(data) + `]}`))
	}))
	defer ts.Close()

	v := NewCloudflareAccessValidator("team", "aud")
	v.certsURL = ts.URL

	keys, err := v.getKeys(context.Background())
	require.Nil(t, err)
	require.Equal(t, 1, len(keys.Keys))
	assert.Equal(t, "srv", keys.Keys[0].KeyID)
}

func TestCFAccessGetKeysDoubleCheckCache(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "dc", Algorithm: "RS256"}

	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	// Should return cached keys without network call
	keys, err := v.getKeys(context.Background())
	require.Nil(t, err)
	assert.Equal(t, "dc", keys.Keys[0].KeyID)
}

func TestCFIdentityFromContext(t *testing.T) {
	id := &CFAccessIdentity{Subject: "sub123", Email: "user@example.com"}
	ctx := context.WithValue(context.Background(), cfIdentityKey, id)
	got := CFIdentityFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, "sub123", got.Subject)
	assert.Equal(t, "user@example.com", got.Email)

	// nil when not set
	got = CFIdentityFromContext(context.Background())
	assert.Nil(t, got)
}

func TestRequireCFAccessSetsIdentityInContext(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "ctx", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "ctx", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	stdClaims := jwt.Claims{
		Subject:   "test-subject",
		Audience:  jwt.Audience{"aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	customClaims := struct {
		Email string `json:"email"`
	}{Email: "test@example.com"}
	token, _ := jwt.Signed(signer).Claims(stdClaims).Claims(customClaims).Serialize()

	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()

	var capturedIdentity *CFAccessIdentity
	handler := v.RequireCFAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIdentity = CFIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, capturedIdentity)
	assert.Equal(t, "test-subject", capturedIdentity.Subject)
	assert.Equal(t, "test@example.com", capturedIdentity.Email)
}

func TestValidateRequestNoMatchingKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "signing-key", Algorithm: "RS256"}

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherPub := jose.JSONWebKey{Key: &otherKey.PublicKey, KeyID: "other-key", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	claims := jwt.Claims{
		Audience:  jwt.Audience{"aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}
	token, _ := jwt.Signed(signer).Claims(claims).Serialize()

	v := NewCloudflareAccessValidator("team", "aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{otherPub}}
	v.fetched = time.Now()

	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", token)

	_, err := v.ValidateRequest(req)
	require.NotNil(t, err)
}
