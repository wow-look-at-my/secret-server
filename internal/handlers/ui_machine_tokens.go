package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

// Machine-token admin UI pages. Routes are registered in UIHandler.Register.
// A machine token is bound to a policy and vends that policy's authorized
// secrets to non-Actions clients (see internal/database/machine_tokens.go).

func (h *UIHandler) listMachineTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.db.ListMachineTokens()
	if err != nil {
		slog.Error("list machine tokens failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "machine_tokens_list.html", map[string]any{"Tokens": tokens})
}

func (h *UIHandler) newMachineToken(w http.ResponseWriter, r *http.Request) {
	policies, _ := h.db.ListPolicies()
	h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{"Policies": policies})
}

func (h *UIHandler) createMachineToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	policyID := r.FormValue("policy_id")

	renderErr := func(msg string) {
		policies, _ := h.db.ListPolicies()
		h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
			"Error":    msg,
			"Form":     r.Form,
			"Policies": policies,
		})
	}

	if name == "" {
		renderErr("Name is required.")
		return
	}
	policy, err := h.db.GetPolicy(policyID)
	if err != nil {
		slog.Error("lookup policy for machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if policy == nil {
		renderErr("Select a valid policy.")
		return
	}

	token, rec, err := h.db.CreateMachineToken(name, policyID)
	if err != nil {
		slog.Error("create machine token failed", "error", err)
		renderErr("Failed to create machine token. Check server logs for details.")
		return
	}

	details, _ := json.Marshal(map[string]string{"name": name, "policy": policy.Name})
	if err := h.audit.CreateEntry("machine_token.create", "admin", uiActor(r), "machine_token", rec.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	// Show the token exactly once — it is not recoverable later.
	h.tmpl.Render(w, r, "machine_token_created.html", map[string]any{
		"Token":  token,
		"Name":   name,
		"Policy": policy.Name,
	})
}

func (h *UIHandler) deleteMachineTokenForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeleteMachineToken(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("delete machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := h.audit.CreateEntry("machine_token.delete", "admin", uiActor(r), "machine_token", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/machine-tokens", http.StatusSeeOther)
}
