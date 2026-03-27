package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

type PublicHandler struct {
	db       *database.DB
	oidc     *auth.GitHubOIDCValidator
}

func NewPublicHandler(db *database.DB, oidc *auth.GitHubOIDCValidator) *PublicHandler {
	return &PublicHandler{db: db, oidc: oidc}
}

func (h *PublicHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+GitHubPrefix+"/secrets", h.fetchSecrets)
}

func (h *PublicHandler) fetchSecrets(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"error":"missing Bearer token"}`, http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := h.oidc.ValidateToken(r.Context(), token)
	if err != nil {
		slog.Warn("OIDC validation failed", "error", err)
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	slog.Info("OIDC token validated",
		"repository", claims.Repository,
		"ref", claims.Ref,
		"workflow", claims.Workflow,
	)

	policies, err := h.db.MatchingPolicies(claims.Repository, claims.Ref)
	if err != nil {
		slog.Error("failed to match policies", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if len(policies) == 0 {
		slog.Info("no matching policies",
			"repository", claims.Repository,
			"ref", claims.Ref,
		)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}

	// Collect secrets from all matching policies (deduplicate by key)
	result := make(map[string]string)
	seen := make(map[string]bool)
	for _, p := range policies {
		pairKey := p.Project + "/" + p.Environment
		if seen[pairKey] {
			continue
		}
		seen[pairKey] = true

		secrets, err := h.db.GetSecretsByProjectEnv(p.Project, p.Environment)
		if err != nil {
			slog.Error("failed to get secrets", "project", p.Project, "environment", p.Environment, "error", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		for k, v := range secrets {
			result[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
