package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

// policyListView pairs a policy with the count of nodes it's attached to.
// Used by the policies_list template.
type policyListView struct {
	database.Policy
	AttachedNodeCount int64
}

func (h *UIHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policies, err := h.db.ListPolicies()
	if err != nil {
		slog.Error("list policies failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	views := make([]policyListView, 0, len(policies))
	for _, p := range policies {
		cnt, err := h.db.Q().CountNodesReferencingPolicy(ctx, p.ID)
		if err != nil {
			slog.Error("count nodes referencing policy failed", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		views = append(views, policyListView{Policy: p, AttachedNodeCount: cnt})
	}
	h.tmpl.Render(w, r, "policies_list.html", views)
}

func (h *UIHandler) newPolicy(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, r, "policy_form.html", map[string]any{
		"IsNew": true,
	})
}

func (h *UIHandler) editPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policy, err := h.db.GetPolicy(id)
	if err != nil {
		slog.Error("get policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if policy == nil {
		http.NotFound(w, r)
		return
	}
	h.tmpl.Render(w, r, "policy_form.html", map[string]any{
		"IsNew":  false,
		"Policy": policy,
	})
}

// parsePolicyPatternsForm extracts and validates the three pattern lists
// from an access-policy form submission. No kind defaults to ["*"]: an empty
// list of any kind is stored as-is and matches nothing (its inner JOIN in
// MatchingPolicyIDs yields no rows), so the policy is fail-closed — it grants
// no access until patterns are added, and "*" must be written explicitly.
// This is what stops a blank ref/actor from silently widening a policy to
// "any ref / any actor" (a dangerous default on a policy that grants
// high-value secrets like a GitHub App private key). It also lets a
// placeholder policy be saved now and filled in later, and matches the
// machine-token policies whose patterns are intentionally left empty (they
// are never consulted on the machine-token vend path).
func parsePolicyPatternsForm(r *http.Request) (repo, ref, actor []string, err error) {
	repo = parsePatternLines(r.FormValue("repository_patterns"))
	ref = parsePatternLines(r.FormValue("ref_patterns"))
	actor = parsePatternLines(r.FormValue("actor_patterns"))
	for _, list := range [][]string{repo, ref, actor} {
		if err := database.ValidatePatterns(list); err != nil {
			return nil, nil, nil, err
		}
	}
	return repo, ref, actor, nil
}

func (h *UIHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	repoPatterns, refPatterns, actorPatterns, err := parsePolicyPatternsForm(r)
	if err != nil {
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew": true,
			"Error": err.Error(),
			"Form":  r.Form,
		})
		return
	}
	policy, err := h.db.CreatePolicy(r.FormValue("name"), repoPatterns, refPatterns, actorPatterns)
	if err != nil {
		slog.Error("create policy failed", "error", err)
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew": true,
			"Error": "Failed to create policy. Check server logs.",
			"Form":  r.Form,
		})
		return
	}
	details, _ := json.Marshal(map[string]any{
		"name":                r.FormValue("name"),
		"repository_patterns": repoPatterns,
		"ref_patterns":        refPatterns,
		"actor_patterns":      actorPatterns,
	})
	if err := h.audit.CreateEntry("policy.create", "admin", uiActor(r), "policy", policy.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/policies", http.StatusSeeOther)
}

func (h *UIHandler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	repoPatterns, refPatterns, actorPatterns, err := parsePolicyPatternsForm(r)
	if err != nil {
		existing, _ := h.db.GetPolicy(id)
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew":  false,
			"Policy": existing,
			"Error":  err.Error(),
			"Form":   r.Form,
		})
		return
	}
	if err := h.db.UpdatePolicy(id, r.FormValue("name"), repoPatterns, refPatterns, actorPatterns); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("update policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]any{
		"name":                r.FormValue("name"),
		"repository_patterns": repoPatterns,
		"ref_patterns":        refPatterns,
		"actor_patterns":      actorPatterns,
	})
	if err := h.audit.CreateEntry("policy.update", "admin", uiActor(r), "policy", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/policies", http.StatusSeeOther)
}

func (h *UIHandler) deletePolicyForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeletePolicy(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("delete policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := h.audit.CreateEntry("policy.delete", "admin", uiActor(r), "policy", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/policies", http.StatusSeeOther)
}
