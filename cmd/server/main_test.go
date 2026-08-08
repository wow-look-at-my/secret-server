package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wow-look-at-my/secret-server/internal/config"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/handlers"
)

func testDB(t *testing.T) (*database.DB, *database.AuditDB) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)
	f, err := os.CreateTemp(t.TempDir(), "test-*.db")
	require.Nil(t, err)
	f.Close()
	db, err := database.New(f.Name(), enc)
	require.Nil(t, err)

	af, err := os.CreateTemp(t.TempDir(), "test-audit-*.db")
	require.Nil(t, err)
	af.Close()
	auditDB, err := database.NewAuditDB(af.Name())
	require.Nil(t, err)

	t.Cleanup(func() { db.Close(); auditDB.Close() })
	return db, auditDB
}

func TestBuildMux(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		ListenAddr:            ":0",
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)
	require.NotNil(t, mux)
}

func TestHealthEndpoint(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "ok", rr.Body.String())
}

// docker-updater probes these two by itself, with no configuration, and reads
// only the status code. They must answer without a credential: the prober has
// none, and a 401 reads as "serving but unhealthy" rather than "not configured".
func TestUpdateCheckEndpoints(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	for _, path := range []string{
		"/.well-known/docker-updater/health",
		"/.well-known/docker-updater/pre-update",
	} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		assert.Equal(t, http.StatusOK, rr.Code, path)
	}
}

// The health endpoint's job is to notice what an HTTP 200 alone cannot: the
// process still serving while the database behind it has stopped answering.
func TestUpdateCheckHealthFailsOnDeadDatabase(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)
	require.Nil(t, db.Close())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/.well-known/docker-updater/health", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestLlmsTxtEndpoint(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	// Public like /health: served directly, no CF Access, no redirect.
	req := httptest.NewRequest("GET", "/llms.txt", nil)
	req.Host = "secrets.pazer.io"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "https://secrets.pazer.io/github/v1/secrets")
	assert.NotContains(t, rr.Body.String(), "{{BASE_URL}}")
}

func TestRootRedirect(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, handlers.AdminPrefix+"/", rr.Header().Get("Location"))
}

func TestRootNotFoundForOtherPaths(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminRequiresCFAccess(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	// Admin endpoint without CF Access token should be unauthorized
	req := httptest.NewRequest("POST", handlers.AdminPrefix+"/v1/nodes", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestUIRequiresCFAccess(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", handlers.AdminPrefix+"/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestPublicAPINoAuth(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	// Public endpoint returns 401 for missing Bearer, not CF Access 401
	req := httptest.NewRequest("GET", handlers.GitHubPrefix+"/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Bearer")
}

func TestSecurityHeaders(t *testing.T) {
	db, auditDB := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain:    "team",
		CFAccessAdminAudience: "aud",
	}
	mux, err := buildMux(db, auditDB, cfg)
	require.Nil(t, err)

	// Security headers should appear on all responses (e.g. /health).
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
	assert.Contains(t, rr.Header().Get("Strict-Transport-Security"), "max-age=")
	assert.Equal(t, "strict-origin-when-cross-origin", rr.Header().Get("Referrer-Policy"))
	assert.Contains(t, rr.Header().Get("Permissions-Policy"), "camera=()")

	// Public API should also have security headers.
	req = httptest.NewRequest("GET", handlers.GitHubPrefix+"/secrets", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
	// Public API should NOT have CSP (that's UI-only).
	assert.Empty(t, rr.Header().Get("Content-Security-Policy"))
}

func TestSetupLogging(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "unknown"} {
		setupLogging(level) // should not panic
	}
}

func TestBuildVersion(t *testing.T) {
	// buildVersion reads debug.ReadBuildInfo; in test binaries this returns
	// build info but without vcs settings, so the result should be empty.
	v := buildVersion()
	// Just verify it doesn't panic and returns a string.
	_ = v
}
