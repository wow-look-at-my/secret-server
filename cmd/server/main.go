package main

import (
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"

	"github.com/go-chi/chi/v5"
	gorillacsrf "github.com/gorilla/csrf"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/config"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/handlers"
	"github.com/wow-look-at-my/secret-server/internal/templates"
)

// securityHeaders sets common security headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// uiSecurityHeaders adds Content-Security-Policy for HTML pages served under
// the admin UI prefix.
func uiSecurityHeaders(next http.Handler) http.Handler {
	csp := strings.Join([]string{
		"default-src 'none'",
		"script-src 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline'",
		"frame-ancestors 'none'",
	}, "; ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	setupLogging(cfg.LogLevel)

	enc, err := crypto.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		slog.Error("failed to create encryptor", "error", err)
		os.Exit(1)
	}

	db, err := database.New(cfg.DatabasePath, enc)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	auditDB, err := database.NewAuditDB(cfg.AuditDatabasePath)
	if err != nil {
		slog.Error("failed to open audit database", "error", err)
		os.Exit(1)
	}
	defer auditDB.Close()

	r, err := buildMux(db, auditDB, cfg)
	if err != nil {
		slog.Error("failed to build routes", "error", err)
		os.Exit(1)
	}

	slog.Info("starting server", "addr", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, r); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > 7 {
		revision = revision[:7]
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}

func buildMux(db *database.DB, auditDB *database.AuditDB, cfg *config.Config) (chi.Router, error) {
	tmpl, err := templates.New(handlers.AdminPrefix, buildVersion())
	if err != nil {
		return nil, err
	}

	oidcValidator := auth.NewGitHubOIDCValidator(cfg.OIDCAudience)
	cfValidator := auth.NewCloudflareAccessValidator(cfg.CFAccessTeamDomain, cfg.CFAccessAdminAudience)

	r := chi.NewRouter()
	r.Use(securityHeaders)

	// Public API — GitHub OIDC auth (no CF Access, no CSRF)
	publicHandler := handlers.NewPublicHandler(db, auditDB, oidcValidator)
	publicHandler.Register(r)

	// Health check — accessed directly, not through CF Access
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Admin API — behind CF Access (no CSRF — JSON API)
	adminHandler := handlers.NewAdminHandler(db, auditDB)
	r.Group(func(r chi.Router) {
		r.Use(cfValidator.RequireCFAccess)
		adminHandler.Register(r)
	})

	// Admin UI — behind CF Access + CSRF protection
	csrfMiddleware := gorillacsrf.Protect(
		cfg.CSRFKey,
		gorillacsrf.FieldName("csrf_token"),
		gorillacsrf.Secure(true),
		gorillacsrf.SameSite(gorillacsrf.SameSiteStrictMode),
		gorillacsrf.Path("/"),
	)
	uiHandler := handlers.NewUIHandler(db, auditDB, tmpl)
	r.Group(func(r chi.Router) {
		r.Use(cfValidator.RequireCFAccess)
		r.Use(csrfMiddleware)
		r.Use(uiSecurityHeaders)
		uiHandler.Register(r)
	})

	// Redirect root to admin UI
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, handlers.AdminPrefix+"/", http.StatusFound)
	})

	return r, nil
}

func setupLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
}
