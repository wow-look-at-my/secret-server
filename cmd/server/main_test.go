package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/wow-look-at-my/secret-server/internal/config"
	"github.com/wow-look-at-my/secret-server/internal/handlers"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func testDB(t *testing.T) *database.DB {
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
	t.Cleanup(func() { db.Close() })
	return db
}

func TestBuildMux(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		ListenAddr:         ":0",
		CFAccessTeamDomain: "team",
		CFAccessAdminAudience:   "aud",
	}
	mux, err := buildMux(db, cfg)
	require.Nil(t, err)
	require.NotNil(t, mux)
}

func TestHealthEndpoint(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain: "team",
		CFAccessAdminAudience:   "aud",
	}
	mux, err := buildMux(db, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", "/github/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "ok", rr.Body.String())
}

func TestRootRedirect(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain: "team",
		CFAccessAdminAudience:   "aud",
	}
	mux, err := buildMux(db, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, handlers.AdminPrefix+"/", rr.Header().Get("Location"))
}

func TestRootNotFoundForOtherPaths(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain: "team",
		CFAccessAdminAudience:   "aud",
	}
	mux, err := buildMux(db, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAdminRequiresCFAccess(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain: "team",
		CFAccessAdminAudience:   "aud",
	}
	mux, err := buildMux(db, cfg)
	require.Nil(t, err)

	// Admin endpoint without CF Access token should be unauthorized
	req := httptest.NewRequest("POST", handlers.AdminPrefix+"/v1/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestUIRequiresCFAccess(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain: "team",
		CFAccessAdminAudience:   "aud",
	}
	mux, err := buildMux(db, cfg)
	require.Nil(t, err)

	req := httptest.NewRequest("GET", handlers.AdminPrefix+"/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestPublicAPINoAuth(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		CFAccessTeamDomain: "team",
		CFAccessAdminAudience:   "aud",
	}
	mux, err := buildMux(db, cfg)
	require.Nil(t, err)

	// Public endpoint returns 401 for missing Bearer, not CF Access 401
	req := httptest.NewRequest("POST", handlers.GitHubPrefix+"/secrets", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Bearer")
}

func TestSetupLogging(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "unknown"} {
		setupLogging(level) // should not panic
	}
}
