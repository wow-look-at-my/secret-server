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

// Machine-token admin UI pages. Split out of ui.go to keep that file under the
// repo's per-file line cap; the routes are still registered in UIHandler.Register.

func (h *UIHandler) listMachineTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.db.ListMachineTokens()
	if err != nil {
		slog.Error("list machine tokens failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "machine_tokens_list.html", map[string]any{
		"Tokens": tokens,
	})
}

func (h *UIHandler) newMachineToken(w http.ResponseWriter, r *http.Request) {
	envs, _ := h.db.ListEnvironments()
	h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
		"Environments": envs,
	})
}

func (h *UIHandler) createMachineToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
			"Error":        "Name is required.",
			"Form":         r.Form,
			"Environments": envs,
		})
		return
	}
	envID, err := h.resolveEnvID(r)
	if err != nil {
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
			"Error":        "Invalid environment: " + err.Error(),
			"Form":         r.Form,
			"Environments": envs,
		})
		return
	}

	token, rec, err := h.db.CreateMachineToken(name, envID)
	if err != nil {
		slog.Error("create machine token failed", "error", err)
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
			"Error":        "Failed to create machine token. Check server logs for details.",
			"Form":         r.Form,
			"Environments": envs,
		})
		return
	}

	env, _ := h.db.GetEnvironment(envID)
	project, environment := "", ""
	if env != nil {
		project, environment = env.Project, env.Environment
	}
	details, _ := json.Marshal(map[string]string{"name": name, "project": project, "environment": environment})
	if err := h.audit.CreateEntry("machine_token.create", "admin", uiActor(r), "machine_token", rec.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	// The plaintext token is shown exactly once — it is not recoverable later.
	h.tmpl.Render(w, r, "machine_token_created.html", map[string]any{
		"Token":       token,
		"Name":        name,
		"Project":     project,
		"Environment": environment,
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
