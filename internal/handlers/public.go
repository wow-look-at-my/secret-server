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

func (h *PublicHandler) fetchSecrets(w http.ResponseWriter, r *http.Request) {
	// Limit request body to prevent abuse (this is a GET endpoint but limit anyway).
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

	// Two credential types share this endpoint. A machine token (issued for
	// non-Actions clients that can't present a GitHub OIDC JWT) is recognizable
	// by its prefix; anything else is validated as an OIDC token. Keeping both
	// on one route means no extra Cloudflare Access bypass path to configure.
	if strings.HasPrefix(token, database.MachineTokenPrefix) {
		h.fetchSecretsMachine(w, r, token)
		return
	}

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

	policies, err := h.db.MatchingPolicies(claims.Repository, claims.Ref, claims.Actor)
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

	if len(policies) == 0 {
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

	// Collect secrets from all matching policies (deduplicate by environment ID)
	result := make(map[string]string)
	seen := make(map[string]bool)
	for _, p := range policies {
		if seen[p.EnvironmentID] {
			continue
		}
		seen[p.EnvironmentID] = true

		secrets, err := h.db.GetSecretsByEnvironmentID(p.EnvironmentID)
		if err != nil {
			slog.Error("failed to get secrets", "project", p.Project, "environment", p.Environment, "error", err)
			h.logAccessDenied("github_actions", claims.Repository, "secret_retrieval_error", map[string]any{
				"repository":  claims.Repository,
				"ref":         claims.Ref,
				"actor":       claims.Actor,
				"workflow":    claims.Workflow,
				"project":     p.Project,
				"environment": p.Environment,
				"error":       err.Error(),
			})
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
		"actor":         claims.Actor,
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

// fetchSecretsMachine vends secrets to a machine token (a bearer credential for
// clients that can't present a GitHub OIDC JWT, e.g. webhook-runner hooks). The
// token is bound to exactly one environment; access is the token's existence,
// not a policy match. Mirrors fetchSecrets' audit/deny shape.
func (h *PublicHandler) fetchSecretsMachine(w http.ResponseWriter, r *http.Request, token string) {
	rec, err := h.db.LookupMachineToken(token)
	if err != nil {
		slog.Error("machine token lookup failed", "error", err)
		h.logAccessDenied("machine_token", "unknown", "machine_token_lookup_error", map[string]any{
			"remote_addr": r.RemoteAddr,
			"error":       err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if rec == nil {
		// Unknown or revoked token. Never echo the token itself.
		h.logAccessDenied("machine_token", "unknown", "invalid_machine_token", map[string]any{
			"remote_addr": r.RemoteAddr,
		})
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	slog.Info("machine token validated",
		"token_id", rec.ID,
		"token_name", rec.Name,
		"project", rec.Project,
		"environment", rec.Environment,
	)

	// Record usage best-effort — a failed timestamp update must not block the vend.
	if err := h.db.TouchMachineToken(rec.ID); err != nil {
		slog.Warn("failed to record machine token usage", "token_id", rec.ID, "error", err)
	}

	secrets, err := h.db.GetSecretsByEnvironmentID(rec.EnvironmentID)
	if err != nil {
		slog.Error("failed to get secrets for machine token", "token_id", rec.ID, "error", err)
		h.logAccessDenied("machine_token", rec.Name, "secret_retrieval_error", map[string]any{
			"token_id":    rec.ID,
			"project":     rec.Project,
			"environment": rec.Environment,
			"error":       err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]any{
		"token_id":      rec.ID,
		"token_name":    rec.Name,
		"project":       rec.Project,
		"environment":   rec.Environment,
		"secrets_count": len(secrets),
	})
	if err := h.audit.CreateEntry("secret.access", "machine_token", rec.Name, "secret", rec.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secrets)
}
