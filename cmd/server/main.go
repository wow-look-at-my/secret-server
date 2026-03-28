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

	mux, err := buildMux(db, cfg)
	if err != nil {
		slog.Error("failed to build routes", "error", err)
		os.Exit(1)
	}

	slog.Info("starting server", "addr", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func buildMux(db *database.DB, cfg *config.Config) (*http.ServeMux, error) {
	tmpl, err := templates.New(handlers.AdminPrefix)
	if err != nil {
		return nil, err
	}

	oidcValidator := auth.NewGitHubOIDCValidator(cfg.OIDCAudience)
	cfValidator := auth.NewCloudflareAccessValidator(cfg.CFAccessTeamDomain, cfg.CFAccessAdminAudience)

	mux := http.NewServeMux()

	// Public API — GitHub OIDC auth (no CF Access)
	publicHandler := handlers.NewPublicHandler(db, oidcValidator)
	publicHandler.Register(mux)

	// Health check — under /github so CF Access bypass covers it
	mux.HandleFunc("GET /github/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Admin API — behind CF Access
	cfAdmin := cfValidator.RequireCFAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminMux := http.NewServeMux()
		adminHandler := handlers.NewAdminHandler(db)
		adminHandler.Register(adminMux)
		adminMux.ServeHTTP(w, r)
	}))
	ap := handlers.AdminPrefix + "/v1"
	mux.HandleFunc("POST "+ap+"/secrets", func(w http.ResponseWriter, r *http.Request) { cfAdmin.ServeHTTP(w, r) })
	mux.HandleFunc("PUT "+ap+"/secrets/{id}", func(w http.ResponseWriter, r *http.Request) { cfAdmin.ServeHTTP(w, r) })
	mux.HandleFunc("DELETE "+ap+"/secrets/{id}", func(w http.ResponseWriter, r *http.Request) { cfAdmin.ServeHTTP(w, r) })
	mux.HandleFunc("POST "+ap+"/policies", func(w http.ResponseWriter, r *http.Request) { cfAdmin.ServeHTTP(w, r) })
	mux.HandleFunc("PUT "+ap+"/policies/{id}", func(w http.ResponseWriter, r *http.Request) { cfAdmin.ServeHTTP(w, r) })
	mux.HandleFunc("DELETE "+ap+"/policies/{id}", func(w http.ResponseWriter, r *http.Request) { cfAdmin.ServeHTTP(w, r) })

	// UI — behind CF Access
	uiMux := http.NewServeMux()
	uiHandler := handlers.NewUIHandler(db, tmpl)
	uiHandler.Register(uiMux)
	cfUI := cfValidator.RequireCFAccess(uiMux)
	mux.HandleFunc("GET "+handlers.AdminPrefix+"/", func(w http.ResponseWriter, r *http.Request) { cfUI.ServeHTTP(w, r) })
	mux.HandleFunc("POST "+handlers.AdminPrefix+"/", func(w http.ResponseWriter, r *http.Request) { cfUI.ServeHTTP(w, r) })

	// Redirect root to admin UI
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, handlers.AdminPrefix+"/", http.StatusFound)
	})

	return mux, nil
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
