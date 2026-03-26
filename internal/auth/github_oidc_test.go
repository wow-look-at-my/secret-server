package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestValidateTokenValid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "kid1", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "kid1", Algorithm: "RS256"}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}

	stdClaims := jwt.Claims{
		Issuer:    "https://token.actions.githubusercontent.com",
		Subject:   "repo:myorg/myrepo:ref:refs/heads/main",
		Audience:  jwt.Audience{"https://secrets.example.com"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	customClaims := GitHubClaims{
		Repository:      "myorg/myrepo",
		RepositoryOwner: "myorg",
		Workflow:        "deploy",
		Ref:             "refs/heads/main",
		Environment:     "production",
	}

	token, err := jwt.Signed(signer).Claims(stdClaims).Claims(customClaims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	v := NewGitHubOIDCValidator("https://secrets.example.com")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()
	v.jwksURL = "cached"

	claims, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.Repository != "myorg/myrepo" {
		t.Errorf("Repository = %q", claims.Repository)
	}
	if claims.RepositoryOwner != "myorg" {
		t.Errorf("RepositoryOwner = %q", claims.RepositoryOwner)
	}
	if claims.Ref != "refs/heads/main" {
		t.Errorf("Ref = %q", claims.Ref)
	}
	if claims.Subject != "repo:myorg/myrepo:ref:refs/heads/main" {
		t.Errorf("Subject = %q", claims.Subject)
	}
}

func TestValidateTokenExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "kid2", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "kid2", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	stdClaims := jwt.Claims{
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: jwt.Audience{"aud"},
		Expiry:   jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}
	token, _ := jwt.Signed(signer).Claims(stdClaims).Serialize()

	v := NewGitHubOIDCValidator("aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()
	v.jwksURL = "cached"

	_, err := v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateTokenWrongIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "kid3", Algorithm: "RS256"}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "kid3", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	stdClaims := jwt.Claims{
		Issuer:    "https://evil.example.com",
		Audience:  jwt.Audience{"aud"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}
	token, _ := jwt.Signed(signer).Claims(stdClaims).Serialize()

	v := NewGitHubOIDCValidator("aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	v.fetched = time.Now()
	v.jwksURL = "cached"

	_, err := v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestValidateTokenNoMatchingKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: key, KeyID: "kid4", Algorithm: "RS256"}

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherPub := jose.JSONWebKey{Key: &otherKey.PublicKey, KeyID: "other-kid", Algorithm: "RS256"}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	token, _ := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: jwt.Audience{"aud"},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()

	v := NewGitHubOIDCValidator("aud")
	v.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{otherPub}}
	v.fetched = time.Now()
	v.jwksURL = "cached"

	_, err := v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for no matching key")
	}
}

func TestDiscoverAndFetchJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "dk", Algorithm: "RS256"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": jwksServer.URL})
	}))
	defer discoveryServer.Close()

	v := NewGitHubOIDCValidator("aud")

	// Override the discovery URL by pre-setting jwksURL
	v.jwksURL = jwksServer.URL

	keys, err := v.getKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys.Keys))
	}
	if keys.Keys[0].KeyID != "dk" {
		t.Errorf("KeyID = %q, want %q", keys.Keys[0].KeyID, "dk")
	}
}
