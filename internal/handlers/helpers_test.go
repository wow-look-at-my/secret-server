package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/templates"
	"github.com/wow-look-at-my/testify/require"
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

	tmpl, err := templates.New(AdminPrefix)
	require.Nil(t, err)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{Key: rsaKey, KeyID: "test", Algorithm: "RS256"}
	pub := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "test", Algorithm: "RS256"}

	oidc := auth.NewGitHubOIDCValidator("https://secrets.example.com")
	auth.SetJWKSForTesting(oidc, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})

	// Pre-create common environments used by handler tests.
	for _, pair := range [][2]string{
		{"app", "prod"}, {"app", "staging"}, {"app", "dev"},
		{"proj", "prod"}, {"proj", "dev"}, {"proj", "env"},
		{"testproj", "staging"}, {"other", "prod"},
		{"myapp", "prod"},
	} {
		db.CreateEnvironment(pair[0], pair[1])
	}

	return &testEnv{db: db, audit: auditDB, tmpl: tmpl, key: rsaKey, jwk: jwk, pub: pub, oidc: oidc}
}

// envID returns the environment ID for a project+environment pair, for use in form tests.
func (e *testEnv) envID(t *testing.T, project, environment string) string {
	t.Helper()
	envs, err := e.db.ListEnvironments()
	require.Nil(t, err)
	for _, env := range envs {
		if env.Project == project && env.Environment == environment {
			return env.ID
		}
	}
	t.Fatalf("environment %s/%s not found in test setup", project, environment)
	return ""
}

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

func makeOIDCToken(t *testing.T, jwk jose.JSONWebKey, repo, ref string) string {
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
		Ref             string `json:"ref"`
	}{
		Repository:      repo,
		RepositoryOwner: strings.Split(repo, "/")[0],
		Ref:             ref,
	}
	token, err := jwt.Signed(signer).Claims(stdClaims).Claims(customClaims).Serialize()
	require.Nil(t, err)

	return token
}
