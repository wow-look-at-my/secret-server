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
	db    *database.DB
	audit *database.AuditDB
	oidc  *auth.GitHubOIDCValidator
}

func NewPublicHandler(db *database.DB, audit *database.AuditDB, oidc *auth.GitHubOIDCValidator) *PublicHandler {
	return &PublicHandler{db: db, audit: audit, oidc: oidc}
}

func (h *PublicHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /public/v1/secrets", h.fetchSecrets)
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

	policyIDs := make([]string, len(policies))
	for i, p := range policies {
		policyIDs[i] = p.ID
	}
	details, _ := json.Marshal(map[string]any{
		"repository":    claims.Repository,
		"ref":           claims.Ref,
		"workflow":      claims.Workflow,
		"policies":      policyIDs,
		"secrets_count": len(result),
	})
	if err := h.audit.CreateEntry("secret.access", "github_actions", claims.Repository, "secret", "", string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
