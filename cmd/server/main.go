package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/config"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/handlers"
	"github.com/wow-look-at-my/secret-server/internal/templates"
)

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

	tmpl, err := templates.New()
	if err != nil {
		slog.Error("failed to parse templates", "error", err)
		os.Exit(1)
	}

	oidcValidator := auth.NewGitHubOIDCValidator(cfg.OIDCAudience)
	cfValidator := auth.NewCloudflareAccessValidator(cfg.CFAccessTeamDomain, cfg.CFAccessAudience)

	mux := http.NewServeMux()

	// Public API — GitHub OIDC auth (no CF Access)
	publicHandler := handlers.NewPublicHandler(db, oidcValidator)
	publicHandler.Register(mux)

	// Admin API — behind CF Access
	adminMux := http.NewServeMux()
	adminHandler := handlers.NewAdminHandler(db)
	adminHandler.Register(adminMux)
	mux.Handle("/admin/", cfValidator.RequireCFAccess(adminMux))

	// UI — behind CF Access
	uiMux := http.NewServeMux()
	uiHandler := handlers.NewUIHandler(db, tmpl)
	uiHandler.Register(uiMux)
	mux.Handle("/ui/", cfValidator.RequireCFAccess(uiMux))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Redirect root to UI
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	slog.Info("starting server", "addr", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
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
