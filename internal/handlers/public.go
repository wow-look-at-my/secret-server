package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/secret-server/client"
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
	// The published client compiles this path in, so serve the symbol it
	// requests rather than a second spelling that can drift from it.
	r.Get(client.SecretsPath, h.fetchSecrets)
	r.Head(GitHubPrefix+"/push-provenance", h.preflightGitHubPushAttestation)
	r.Post(GitHubPrefix+"/push-provenance", h.attestGitHubPushes)
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

	// Two credential types share this endpoint. A machine token (for non-Actions
	// clients that can't present an OIDC JWT, e.g. webhook-runner hooks) is
	// recognizable by its prefix; anything else is validated as an OIDC token.
	// One route → no extra Cloudflare Access bypass path to configure.
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
		"sha", claims.SHA,
		"actor", claims.Actor,
		"actor_id", claims.ActorID,
		"workflow", claims.Workflow,
	)

	actor := claims.Actor
	actorID := claims.ActorID
	identitySource := "github_oidc"
	provenance, err := h.db.FindGitHubPushProvenance(
		r.Context(),
		claims.Repository,
		claims.Ref,
		claims.SHA,
	)
	if err != nil {
		slog.Error("failed to resolve Agent Host push provenance", "error", err)
		h.logAccessDenied("github_actions", claims.ActorID, "provenance_lookup_error", map[string]any{
			"repository":    claims.Repository,
			"ref":           claims.Ref,
			"sha":           claims.SHA,
			"oidc_actor":    claims.Actor,
			"oidc_actor_id": claims.ActorID,
			"error":         err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if provenance != nil {
		actor = provenance.GitHubLogin
		actorID = provenance.GitHubUserID
		identitySource = "agent_host_push"
	}

	policyIDs, err := h.db.MatchingPolicyIDsForIdentity(
		r.Context(),
		claims.Repository,
		claims.Ref,
		actor,
		actorID,
	)
	if err != nil {
		slog.Error("failed to match policies", "error", err)
		h.logAccessDenied("github_actions", actorID, "policy_lookup_error", map[string]any{
			"repository":      claims.Repository,
			"ref":             claims.Ref,
			"sha":             claims.SHA,
			"actor":           actor,
			"actor_id":        actorID,
			"identity_source": identitySource,
			"oidc_actor":      claims.Actor,
			"oidc_actor_id":   claims.ActorID,
			"workflow":        claims.Workflow,
			"error":           err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if len(policyIDs) == 0 {
		slog.Info("no matching policies",
			"repository", claims.Repository,
			"ref", claims.Ref,
		)
		h.logAccessDenied("github_actions", actorID, "no_matching_policies", map[string]any{
			"repository":      claims.Repository,
			"ref":             claims.Ref,
			"sha":             claims.SHA,
			"actor":           actor,
			"actor_id":        actorID,
			"identity_source": identitySource,
			"oidc_actor":      claims.Actor,
			"oidc_actor_id":   claims.ActorID,
			"workflow":        claims.Workflow,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}

	secrets, err := h.db.AuthorizedSecrets(r.Context(), policyIDs)
	if err != nil {
		slog.Error("failed to load authorized secrets", "error", err)
		h.logAccessDenied("github_actions", actorID, "secret_retrieval_error", map[string]any{
			"repository":      claims.Repository,
			"ref":             claims.Ref,
			"sha":             claims.SHA,
			"actor":           actor,
			"actor_id":        actorID,
			"identity_source": identitySource,
			"oidc_actor":      claims.Actor,
			"oidc_actor_id":   claims.ActorID,
			"workflow":        claims.Workflow,
			"error":           err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]any{
		"repository":      claims.Repository,
		"ref":             claims.Ref,
		"sha":             claims.SHA,
		"actor":           actor,
		"actor_id":        actorID,
		"identity_source": identitySource,
		"oidc_actor":      claims.Actor,
		"oidc_actor_id":   claims.ActorID,
		"workflow":        claims.Workflow,
		"policies":        policyIDs,
		"secrets_count":   len(secrets),
	})
	if err := h.audit.CreateEntry("secret.access.granted", "github_actions", actorID, "secret", "", string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secrets)
}

// fetchSecretsMachine vends secrets to a machine token — a bearer credential
// for clients that can't present a GitHub OIDC JWT (e.g. webhook-runner hooks).
// The token is bound to one policy and vends exactly that policy's authorized
// secrets, via the same AuthorizedSecrets path the OIDC flow uses. Mirrors
// fetchSecrets' audit/deny shape; the token itself is never logged.
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
	)

	// Record usage best-effort — a failed timestamp update must not block the vend.
	if err := h.db.TouchMachineToken(rec.ID); err != nil {
		slog.Warn("failed to record machine token usage", "token_id", rec.ID, "error", err)
	}

	secrets, err := h.db.AuthorizedSecretsForToken(r.Context(), rec.ID)
	if err != nil {
		slog.Error("failed to load secrets for machine token", "token_id", rec.ID, "error", err)
		h.logAccessDenied("machine_token", rec.Name, "secret_retrieval_error", map[string]any{
			"token_id": rec.ID,
			"error":    err.Error(),
		})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]any{
		"token_id":      rec.ID,
		"token_name":    rec.Name,
		"secrets_count": len(secrets),
	})
	if err := h.audit.CreateEntry("secret.access.granted", "machine_token", rec.Name, "secret", "", string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secrets)
}
