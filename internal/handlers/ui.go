package handlers

import (
	"log/slog"
	"net/http"

	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/templates"
)

type UIHandler struct {
	db   *database.DB
	tmpl *templates.Templates
}

func NewUIHandler(db *database.DB, tmpl *templates.Templates) *UIHandler {
	return &UIHandler{db: db, tmpl: tmpl}
}

func (h *UIHandler) Register(mux *http.ServeMux) {
	p := AdminPrefix
	mux.HandleFunc("GET "+p+"/", h.dashboard)
	mux.HandleFunc("GET "+p+"/secrets", h.listSecrets)
	mux.HandleFunc("GET "+p+"/secrets/new", h.newSecret)
	mux.HandleFunc("GET "+p+"/secrets/{id}/edit", h.editSecret)
	mux.HandleFunc("POST "+p+"/secrets", h.createSecret)
	mux.HandleFunc("POST "+p+"/secrets/{id}", h.updateSecret)
	mux.HandleFunc("POST "+p+"/secrets/{id}/delete", h.deleteSecretForm)
	mux.HandleFunc("GET "+p+"/policies", h.listPolicies)
	mux.HandleFunc("GET "+p+"/policies/new", h.newPolicy)
	mux.HandleFunc("GET "+p+"/policies/{id}/edit", h.editPolicy)
	mux.HandleFunc("POST "+p+"/policies", h.createPolicy)
	mux.HandleFunc("POST "+p+"/policies/{id}", h.updatePolicy)
	mux.HandleFunc("POST "+p+"/policies/{id}/delete", h.deletePolicyForm)
}

func (h *UIHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != AdminPrefix+"/" {
		http.Redirect(w, r, AdminPrefix+"/", http.StatusFound)
		return
	}
	stats, err := h.db.GetDashboardStats()
	if err != nil {
		slog.Error("dashboard stats failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, "dashboard.html", stats)
}

func (h *UIHandler) listSecrets(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	environment := r.URL.Query().Get("environment")
	secrets, err := h.db.ListSecrets(project, environment)
	if err != nil {
		slog.Error("list secrets failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, "secrets_list.html", map[string]any{
		"Secrets":     secrets,
		"Project":     project,
		"Environment": environment,
	})
}

func (h *UIHandler) newSecret(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, "secret_form.html", map[string]any{
		"IsNew": true,
	})
}

func (h *UIHandler) editSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	secret, err := h.db.GetSecret(id)
	if err != nil {
		slog.Error("get secret failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if secret == nil {
		http.NotFound(w, r)
		return
	}
	h.tmpl.Render(w, "secret_form.html", map[string]any{
		"IsNew":  false,
		"Secret": secret,
	})
}

func (h *UIHandler) createSecret(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	_, err := h.db.CreateSecret(
		r.FormValue("key"),
		r.FormValue("value"),
		r.FormValue("project"),
		r.FormValue("environment"),
	)
	if err != nil {
		slog.Error("create secret failed", "error", err)
		h.tmpl.Render(w, "secret_form.html", map[string]any{
			"IsNew": true,
			"Error": "Failed to create secret: " + err.Error(),
			"Form":  r.Form,
		})
		return
	}
	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) updateSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	err := h.db.UpdateSecret(
		id,
		r.FormValue("key"),
		r.FormValue("value"),
		r.FormValue("project"),
		r.FormValue("environment"),
	)
	if err != nil {
		slog.Error("update secret failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) deleteSecretForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.db.DeleteSecret(id); err != nil {
		slog.Error("delete secret failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.db.ListPolicies()
	if err != nil {
		slog.Error("list policies failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, "policies_list.html", policies)
}

func (h *UIHandler) newPolicy(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, "policy_form.html", map[string]any{
		"IsNew": true,
	})
}

func (h *UIHandler) editPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	h.tmpl.Render(w, "policy_form.html", map[string]any{
		"IsNew":  false,
		"Policy": policy,
	})
}

func (h *UIHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	refPattern := r.FormValue("ref_pattern")
	if refPattern == "" {
		refPattern = "*"
	}
	_, err := h.db.CreatePolicy(
		r.FormValue("name"),
		r.FormValue("repository_pattern"),
		refPattern,
		r.FormValue("project"),
		r.FormValue("environment"),
	)
	if err != nil {
		slog.Error("create policy failed", "error", err)
		h.tmpl.Render(w, "policy_form.html", map[string]any{
			"IsNew": true,
			"Error": "Failed to create policy: " + err.Error(),
			"Form":  r.Form,
		})
		return
	}
	http.Redirect(w, r, AdminPrefix+"/policies", http.StatusSeeOther)
}

func (h *UIHandler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	refPattern := r.FormValue("ref_pattern")
	if refPattern == "" {
		refPattern = "*"
	}
	err := h.db.UpdatePolicy(
		id,
		r.FormValue("name"),
		r.FormValue("repository_pattern"),
		refPattern,
		r.FormValue("project"),
		r.FormValue("environment"),
	)
	if err != nil {
		slog.Error("update policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, AdminPrefix+"/policies", http.StatusSeeOther)
}

func (h *UIHandler) deletePolicyForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.db.DeletePolicy(id); err != nil {
		slog.Error("delete policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, AdminPrefix+"/policies", http.StatusSeeOther)
}
