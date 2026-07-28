package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/templates"
)

type testEnv struct {
	db    *database.DB
	audit *database.AuditDB
	tmpl  *templates.Templates
	key   *rsa.PrivateKey
	jwk   jose.JSONWebKey
	pub   jose.JSONWebKey
	oidc  *auth.GitHubOIDCValidator
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

	auditF, err := os.CreateTemp(t.TempDir(), "test-audit-*.db")
	require.Nil(t, err)
	auditF.Close()
	auditDB, err := database.NewAuditDB(auditF.Name())
	require.Nil(t, err)

	t.Cleanup(func() { db.Close(); auditDB.Close() })

	tmpl, err := templates.New(AdminPrefix, "test")
	require.Nil(t, err)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: rsaKey, KeyID: "test", Algorithm: "RS256"}
	pub := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "test", Algorithm: "RS256"}

	oidc := auth.NewGitHubOIDCValidator("https://secrets.example.com")
	auth.SetJWKSForTesting(oidc, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})

	return &testEnv{db: db, audit: auditDB, tmpl: tmpl, key: rsaKey, jwk: jwk, pub: pub, oidc: oidc}
}

// strPtr is a test helper for building *string values.
func strPtr(s string) *string { return &s }

func setupClosedDB(t *testing.T) *testEnv {
	t.Helper()
	env := setup(t)
	env.db.Close()
	env.audit.Close()
	return env
}

func setupClosedMainDB(t *testing.T) *testEnv {
	t.Helper()
	env := setup(t)
	env.db.Close()
	return env
}

// jsonReq creates an httptest request with Content-Type: application/json.
func jsonReq(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func makeOIDCToken(t *testing.T, jwk jose.JSONWebKey, repo, ref string) string {
	return makeOIDCTokenWithActor(t, jwk, repo, ref, "deploy-bot")
}

func makeOIDCTokenWithActor(t *testing.T, jwk jose.JSONWebKey, repo, ref, actor string) string {
	return makeOIDCTokenFull(t, jwk, repo, ref, actor, "")
}

func makeOIDCTokenWithEnv(t *testing.T, jwk jose.JSONWebKey, repo, ref, environment string) string {
	return makeOIDCTokenFull(t, jwk, repo, ref, "deploy-bot", environment)
}

func makeOIDCTokenFull(t *testing.T, jwk jose.JSONWebKey, repo, ref, actor, environment string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	require.Nil(t, err)

	stdClaims := jwt.Claims{
		Issuer:    "https://token.actions.githubusercontent.com",
		Subject:   "repo:" + repo + ":ref:" + ref,
		Audience:  jwt.Audience{"https://secrets.example.com"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	customClaims := struct {
		Repository      string `json:"repository"`
		RepositoryOwner string `json:"repository_owner"`
		Actor           string `json:"actor"`
		ActorID         string `json:"actor_id"`
		Ref             string `json:"ref"`
		Environment     string `json:"environment,omitempty"`
		SHA             string `json:"sha"`
	}{
		Repository:      repo,
		RepositoryOwner: strings.Split(repo, "/")[0],
		Actor:           actor,
		ActorID:         "583231",
		Ref:             ref,
		Environment:     environment,
		SHA:             strings.Repeat("a", 40),
	}
	token, err := jwt.Signed(signer).Claims(stdClaims).Claims(customClaims).Serialize()
	require.Nil(t, err)

	return token
}
