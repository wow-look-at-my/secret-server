package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/templates"
)

type UIHandler struct {
	db    *database.DB
	audit *database.AuditDB
	tmpl  *templates.Templates
}

func NewUIHandler(db *database.DB, audit *database.AuditDB, tmpl *templates.Templates) *UIHandler {
	return &UIHandler{db: db, audit: audit, tmpl: tmpl}
}

func (h *UIHandler) Register(r chi.Router) {
	p := AdminPrefix
	r.Get(p+"/", h.dashboard)
	r.Get(p+"/secrets", h.listSecrets)
	r.Get(p+"/secrets/new", h.newSecret)
	r.Get(p+"/secrets/{id}/edit", h.editSecret)
	r.Post(p+"/secrets", h.createSecret)
	r.Post(p+"/secrets/{id}", h.updateSecret)
	r.Post(p+"/secrets/{id}/delete", h.deleteSecretForm)
	r.Get(p+"/policies", h.listPolicies)
	r.Get(p+"/policies/new", h.newPolicy)
	r.Get(p+"/policies/{id}/edit", h.editPolicy)
	r.Post(p+"/policies", h.createPolicy)
	r.Post(p+"/policies/{id}", h.updatePolicy)
	r.Post(p+"/policies/{id}/delete", h.deletePolicyForm)
	r.Get(p+"/audit", h.auditLog)
	// Catch-all: redirect unknown /admin/* paths to /admin/
	r.Get(p+"/*", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p+"/", http.StatusFound)
	})
}

func uiActor(r *http.Request) string {
	if id := auth.CFIdentityFromContext(r.Context()); id != nil {
		if id.Email != "" {
			return id.Email
		}
		if id.Subject != "" {
			return id.Subject
		}
	}
	return "unknown"
}

func (h *UIHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetDashboardStats()
	if err != nil {
		slog.Error("dashboard stats failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r,"dashboard.html", stats)
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
	h.tmpl.Render(w, r,"secrets_list.html", map[string]any{
		"Secrets":     secrets,
		"Project":     project,
		"Environment": environment,
	})
}

func (h *UIHandler) newSecret(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, r,"secret_form.html", map[string]any{
		"IsNew": true,
	})
}

func (h *UIHandler) editSecret(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
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
	h.tmpl.Render(w, r,"secret_form.html", map[string]any{
		"IsNew":  false,
		"Secret": secret,
	})
}

func (h *UIHandler) createSecret(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	secret, err := h.db.CreateSecret(
		r.FormValue("key"),
		r.FormValue("value"),
		r.FormValue("project"),
		r.FormValue("environment"),
	)
	if err != nil {
		slog.Error("create secret failed", "error", err)
		h.tmpl.Render(w, r,"secret_form.html", map[string]any{
			"IsNew": true,
			"Error": "Failed to create secret: " + err.Error(),
			"Form":  r.Form,
		})
		return
	}

	details, _ := json.Marshal(map[string]string{"key": r.FormValue("key"), "project": r.FormValue("project"), "environment": r.FormValue("environment")})
	if err := h.audit.CreateEntry("secret.create", "admin", uiActor(r), "secret", secret.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) updateSecret(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	value := r.FormValue("value")
	if value == "" {
		existing, err := h.db.GetSecret(id)
		if err != nil {
			slog.Error("get secret for update failed", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.NotFound(w, r)
			return
		}
		value = existing.Value
	}
	err := h.db.UpdateSecret(
		id,
		r.FormValue("key"),
		value,
		r.FormValue("project"),
		r.FormValue("environment"),
	)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("update secret failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"key": r.FormValue("key"), "project": r.FormValue("project"), "environment": r.FormValue("environment")})
	if err := h.audit.CreateEntry("secret.update", "admin", uiActor(r), "secret", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) deleteSecretForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeleteSecret(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("delete secret failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := h.audit.CreateEntry("secret.delete", "admin", uiActor(r), "secret", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
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
	h.tmpl.Render(w, r,"policies_list.html", policies)
}

func (h *UIHandler) newPolicy(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, r,"policy_form.html", map[string]any{
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
	h.tmpl.Render(w, r,"policy_form.html", map[string]any{
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
	policy, err := h.db.CreatePolicy(
		r.FormValue("name"),
		r.FormValue("repository_pattern"),
		refPattern,
		r.FormValue("project"),
		r.FormValue("environment"),
	)
	if err != nil {
		slog.Error("create policy failed", "error", err)
		h.tmpl.Render(w, r,"policy_form.html", map[string]any{
			"IsNew": true,
			"Error": "Failed to create policy: " + err.Error(),
			"Form":  r.Form,
		})
		return
	}

	details, _ := json.Marshal(map[string]string{"name": r.FormValue("name"), "repository_pattern": r.FormValue("repository_pattern"), "project": r.FormValue("project"), "environment": r.FormValue("environment")})
	if err := h.audit.CreateEntry("policy.create", "admin", uiActor(r), "policy", policy.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/policies", http.StatusSeeOther)
}

func (h *UIHandler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
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
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("update policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"name": r.FormValue("name"), "repository_pattern": r.FormValue("repository_pattern"), "project": r.FormValue("project"), "environment": r.FormValue("environment")})
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

func (h *UIHandler) auditLog(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage := 50
	offset := (page - 1) * perPage

	entries, err := h.audit.ListEntries(perPage, offset)
	if err != nil {
		slog.Error("list audit entries failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	total, _ := h.audit.CountEntries()

	h.tmpl.Render(w, r, "audit_log.html", map[string]any{
		"Entries":  entries,
		"Page":     page,
		"HasNext":  offset+perPage < total,
		"HasPrev":  page > 1,
		"NextPage": page + 1,
		"PrevPage": page - 1,
	})
}
