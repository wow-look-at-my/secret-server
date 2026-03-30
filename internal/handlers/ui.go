package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
	r.Get(p+"/environments", h.listEnvironments)
	r.Get(p+"/environments/new", h.newEnvironment)
	r.Get(p+"/environments/{id}/edit", h.editEnvironment)
	r.Post(p+"/environments", h.createEnvironment)
	r.Post(p+"/environments/{id}", h.updateEnvironment)
	r.Post(p+"/environments/{id}/delete", h.deleteEnvironmentForm)
	r.Get(p+"/audit", h.auditLog)
	r.Get(p+"/style.css", h.tmpl.ServeCSS)
	// Redirect /admin (no trailing slash) to /admin/
	r.Get(p, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p+"/", http.StatusFound)
	})
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

// resolveEnvID looks up an environment by ID from the form and returns the ID.
func (h *UIHandler) resolveEnvID(r *http.Request) (string, error) {
	envID := r.FormValue("env_id")
	if envID == "" {
		return "", fmt.Errorf("environment is required")
	}
	if _, err := uuid.Parse(envID); err != nil {
		return "", fmt.Errorf("invalid environment ID format")
	}
	env, err := h.db.GetEnvironment(envID)
	if err != nil {
		return "", fmt.Errorf("lookup environment: %w", err)
	}
	if env == nil {
		return "", fmt.Errorf("selected environment not found")
	}
	return envID, nil
}

func (h *UIHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetDashboardStats()
	if err != nil {
		slog.Error("dashboard stats failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "dashboard.html", stats)
}

// base64JSONStructure tries to base64-decode a value and parse it as JSON.
// If the value is a base64-encoded JSON object, it returns a redacted version
// showing only top-level keys with "..." as values. Returns empty string otherwise.
func base64JSONStructure(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		// Try URL-safe base64 as well.
		decoded, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return ""
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return ""
	}
	redacted := make(map[string]string, len(obj))
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
		redacted[k] = "..."
	}
	sort.Strings(keys)
	out, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return ""
	}
	return string(out)
}

// --- Secrets ---

func (h *UIHandler) listSecrets(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	environment := r.URL.Query().Get("environment")
	secrets, err := h.db.ListSecrets(project, environment)
	if err != nil {
		slog.Error("list secrets failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	envs, _ := h.db.ListEnvironments()
	// Build unique project names and environment names for filter dropdowns.
	projectSet := make(map[string]bool)
	envNameSet := make(map[string]bool)
	for _, e := range envs {
		projectSet[e.Project] = true
		envNameSet[e.Environment] = true
	}
	var uniqueProjects, uniqueEnvNames []string
	for _, e := range envs {
		if projectSet[e.Project] {
			uniqueProjects = append(uniqueProjects, e.Project)
			delete(projectSet, e.Project)
		}
		if envNameSet[e.Environment] {
			uniqueEnvNames = append(uniqueEnvNames, e.Environment)
			delete(envNameSet, e.Environment)
		}
	}
	h.tmpl.Render(w, r, "secrets_list.html", map[string]any{
		"Secrets":        secrets,
		"Project":        project,
		"Environment":    environment,
		"Environments":   envs,
		"UniqueProjects": uniqueProjects,
		"UniqueEnvNames": uniqueEnvNames,
	})
}

func (h *UIHandler) newSecret(w http.ResponseWriter, r *http.Request) {
	envs, _ := h.db.ListEnvironments()
	h.tmpl.Render(w, r, "secret_form.html", map[string]any{
		"IsNew":        true,
		"Environments": envs,
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
	envs, _ := h.db.ListEnvironments()
	data := map[string]any{
		"IsNew":        false,
		"Secret":       secret,
		"Environments": envs,
	}
	if structure := base64JSONStructure(secret.Value); structure != "" {
		data["JSONStructure"] = structure
	}
	h.tmpl.Render(w, r, "secret_form.html", data)
}

func (h *UIHandler) createSecret(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	envID, err := h.resolveEnvID(r)
	if err != nil {
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "secret_form.html", map[string]any{
			"IsNew":        true,
			"Error":        "Invalid environment: " + err.Error(),
			"Form":         r.Form,
			"Environments": envs,
		})
		return
	}
	secret, err := h.db.CreateSecret(
		r.FormValue("key"),
		r.FormValue("value"),
		envID,
	)
	if err != nil {
		slog.Error("create secret failed", "error", err)
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "secret_form.html", map[string]any{
			"IsNew":        true,
			"Error":        "Failed to create secret. Check server logs for details.",
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
	details, _ := json.Marshal(map[string]string{"key": r.FormValue("key"), "project": project, "environment": environment})
	if err := h.audit.CreateEntry("secret.create", "admin", uiActor(r), "secret", secret.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) updateSecret(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
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
	envID, err := h.resolveEnvID(r)
	if err != nil {
		slog.Error("resolve env for secret update failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = h.db.UpdateSecret(id, r.FormValue("key"), value, envID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("update secret failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	env, _ := h.db.GetEnvironment(envID)
	project, environment := "", ""
	if env != nil {
		project, environment = env.Project, env.Environment
	}
	details, _ := json.Marshal(map[string]string{"key": r.FormValue("key"), "project": project, "environment": environment})
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

// --- Policies ---

func (h *UIHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.db.ListPolicies()
	if err != nil {
		slog.Error("list policies failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "policies_list.html", policies)
}

func (h *UIHandler) newPolicy(w http.ResponseWriter, r *http.Request) {
	envs, _ := h.db.ListEnvironments()
	h.tmpl.Render(w, r, "policy_form.html", map[string]any{
		"IsNew":        true,
		"Environments": envs,
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
	envs, _ := h.db.ListEnvironments()
	h.tmpl.Render(w, r, "policy_form.html", map[string]any{
		"IsNew":        false,
		"Policy":       policy,
		"Environments": envs,
	})
}

func (h *UIHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	refPattern := r.FormValue("ref_pattern")
	if refPattern == "" {
		refPattern = "*"
	}
	envID, err := h.resolveEnvID(r)
	if err != nil {
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew":        true,
			"Error":        "Invalid environment: " + err.Error(),
			"Form":         r.Form,
			"Environments": envs,
		})
		return
	}
	policy, err := h.db.CreatePolicy(
		r.FormValue("name"),
		r.FormValue("repository_pattern"),
		refPattern,
		envID,
	)
	if err != nil {
		slog.Error("create policy failed", "error", err)
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew":        true,
			"Error":        "Failed to create policy. Check server logs for details.",
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
	details, _ := json.Marshal(map[string]string{"name": r.FormValue("name"), "repository_pattern": r.FormValue("repository_pattern"), "project": project, "environment": environment})
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
	refPattern := r.FormValue("ref_pattern")
	if refPattern == "" {
		refPattern = "*"
	}
	envID, err := h.resolveEnvID(r)
	if err != nil {
		slog.Error("resolve env for policy update failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = h.db.UpdatePolicy(id, r.FormValue("name"), r.FormValue("repository_pattern"), refPattern, envID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("update policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	env, _ := h.db.GetEnvironment(envID)
	project, environment := "", ""
	if env != nil {
		project, environment = env.Project, env.Environment
	}
	details, _ := json.Marshal(map[string]string{"name": r.FormValue("name"), "repository_pattern": r.FormValue("repository_pattern"), "project": project, "environment": environment})
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

// --- Environments ---

func (h *UIHandler) listEnvironments(w http.ResponseWriter, r *http.Request) {
	envs, err := h.db.ListEnvironments()
	if err != nil {
		slog.Error("list environments failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "environments_list.html", map[string]any{
		"Environments": envs,
	})
}

func (h *UIHandler) newEnvironment(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, r, "environment_form.html", map[string]any{
		"IsNew": true,
	})
}

func (h *UIHandler) editEnvironment(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	env, err := h.db.GetEnvironment(id)
	if err != nil {
		slog.Error("get environment failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if env == nil {
		http.NotFound(w, r)
		return
	}
	h.tmpl.Render(w, r, "environment_form.html", map[string]any{
		"IsNew":       false,
		"Environment": env,
	})
}

func (h *UIHandler) createEnvironment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	project := r.FormValue("project")
	environment := r.FormValue("environment")
	if project == "" || environment == "" {
		h.tmpl.Render(w, r, "environment_form.html", map[string]any{
			"IsNew": true,
			"Error": "Project and environment are required.",
			"Form":  r.Form,
		})
		return
	}
	env, err := h.db.CreateEnvironment(project, environment)
	if err != nil {
		slog.Error("create environment failed", "error", err)
		h.tmpl.Render(w, r, "environment_form.html", map[string]any{
			"IsNew": true,
			"Error": "Failed to create environment. Check server logs for details.",
			"Form":  r.Form,
		})
		return
	}

	details, _ := json.Marshal(map[string]string{"project": project, "environment": environment})
	if err := h.audit.CreateEntry("environment.create", "admin", uiActor(r), "environment", env.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/environments", http.StatusSeeOther)
}

func (h *UIHandler) updateEnvironment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	project := r.FormValue("project")
	environment := r.FormValue("environment")
	if project == "" || environment == "" {
		env, _ := h.db.GetEnvironment(id)
		h.tmpl.Render(w, r, "environment_form.html", map[string]any{
			"IsNew":       false,
			"Environment": env,
			"Error":       "Project and environment are required.",
			"Form":        r.Form,
		})
		return
	}
	if err := h.db.UpdateEnvironment(id, project, environment); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("update environment failed", "error", err)
		env, _ := h.db.GetEnvironment(id)
		h.tmpl.Render(w, r, "environment_form.html", map[string]any{
			"IsNew":       false,
			"Environment": env,
			"Error":       "Failed to update environment. Check server logs for details.",
			"Form":        r.Form,
		})
		return
	}

	details, _ := json.Marshal(map[string]string{"project": project, "environment": environment})
	if err := h.audit.CreateEntry("environment.update", "admin", uiActor(r), "environment", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/environments", http.StatusSeeOther)
}

func (h *UIHandler) deleteEnvironmentForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	env, err := h.db.GetEnvironment(id)
	if err != nil {
		slog.Error("get environment for delete failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if env == nil {
		http.NotFound(w, r)
		return
	}

	inUse, err := h.db.EnvironmentInUse(id)
	if err != nil {
		slog.Error("check environment in use failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if inUse {
		envs, _ := h.db.ListEnvironments()
		h.tmpl.Render(w, r, "environments_list.html", map[string]any{
			"Environments": envs,
			"Error":        fmt.Sprintf("Cannot delete %s / %s: secrets or policies still reference it. Remove them first.", env.Project, env.Environment),
		})
		return
	}

	if err := h.db.DeleteEnvironment(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("delete environment failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"project": env.Project, "environment": env.Environment})
	if err := h.audit.CreateEntry("environment.delete", "admin", uiActor(r), "environment", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/environments", http.StatusSeeOther)
}

// --- Audit ---

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
