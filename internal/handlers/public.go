package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
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

func (h *PublicHandler) Register(r chi.Router) {
	r.Get(GitHubPrefix+"/secrets", h.fetchSecrets)
}

func (h *PublicHandler) logAccessDenied(actorType, actorID, reason string, extra map[string]any) {
	m := map[string]any{"reason": reason}
	for k, v := range extra {
		m[k] = v
	}
	details, _ := json.Marshal(m)
	if err := h.audit.CreateEntry("secret.access.denied", actorType, actorID, "secret", "", string(details)); err != nil {
		slog.Error("audit log failed for denied access", "error", err, "reason", reason)
	}
}

// fetchSecrets is the hot path for GitHub Actions. It validates an OIDC
// token, matches the claims against policy pattern rows via a single
// SQLite-side GLOB query, then resolves the matching policy IDs to
// authorized leaf secrets through a recursive CTE. The response shape
// is `{secret_name: plaintext}` — secret names are globally unique so
// there is no collision to handle.
func (h *PublicHandler) fetchSecrets(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		h.logAccessDenied("anonymous", "unknown", "missing_token", map[string]any{
			"remote_addr": r.RemoteAddr,
		})
		http.Error(w, `{"error":"missing Bearer token"}`, http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := h.oidc.ValidateToken(r.Context(), token)
	if err != nil {
		slog.Warn("OIDC validation failed", "error", err)
		h.logAccessDenied("anonymous", "unknown", "invalid_token", map[string]any{
			"remote_addr": r.RemoteAddr,
			"error":       err.Error(),
		})
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	slog.Info("OIDC token validated",
		"repository", claims.Repository,
		"ref", claims.Ref,
		"actor", claims.Actor,
		"workflow", claims.Workflow,
	)

	policyIDs, err := h.db.MatchingPolicyIDs(r.Context(), claims.Repository, claims.Ref, claims.Actor)
	if err != nil {
		slog.Error("failed to match policies", "error", err)
		h.logAccessDenied("github_actions", claims.Repository, "policy_lookup_error", map[string]any{
			"repository": claims.Repository,
			"ref":        claims.Ref,
			"actor":      claims.Actor,
			"workflow":   claims.Workflow,
			"error":      err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if len(policyIDs) == 0 {
		slog.Info("no matching policies",
			"repository", claims.Repository,
			"ref", claims.Ref,
		)
		h.logAccessDenied("github_actions", claims.Repository, "no_matching_policies", map[string]any{
			"repository": claims.Repository,
			"ref":        claims.Ref,
			"actor":      claims.Actor,
			"workflow":   claims.Workflow,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}

	secrets, err := h.db.AuthorizedSecrets(r.Context(), policyIDs)
	if err != nil {
		slog.Error("failed to load authorized secrets", "error", err)
		h.logAccessDenied("github_actions", claims.Repository, "secret_retrieval_error", map[string]any{
			"repository": claims.Repository,
			"ref":        claims.Ref,
			"actor":      claims.Actor,
			"workflow":   claims.Workflow,
			"error":      err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]any{
		"repository":    claims.Repository,
		"ref":           claims.Ref,
		"actor":         claims.Actor,
		"workflow":      claims.Workflow,
		"policies":      policyIDs,
		"secrets_count": len(secrets),
	})
	if err := h.audit.CreateEntry("secret.access.granted", "github_actions", claims.Repository, "secret", "", string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secrets)
}
