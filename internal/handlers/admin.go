package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

type AdminHandler struct {
	db    *database.DB
	audit *database.AuditDB
}

func NewAdminHandler(db *database.DB, audit *database.AuditDB) *AdminHandler {
	return &AdminHandler{db: db, audit: audit}
}

func (h *AdminHandler) Register(r chi.Router) {
	p := AdminPrefix + "/v1"
	r.Post(p+"/secrets", h.createSecret)
	r.Put(p+"/secrets/{id}", h.updateSecret)
	r.Delete(p+"/secrets/{id}", h.deleteSecret)
	r.Post(p+"/policies", h.createPolicy)
	r.Put(p+"/policies/{id}", h.updatePolicy)
	r.Delete(p+"/policies/{id}", h.deletePolicy)
	r.Get(p+"/environments", h.listEnvironments)
	r.Post(p+"/environments", h.createEnvironment)
	r.Delete(p+"/environments/{id}", h.deleteEnvironment)
}

func adminActor(r *http.Request) string {
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

func (h *AdminHandler) createSecret(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key         string `json:"key"`
		Value       string `json:"value"`
		Project     string `json:"project"`
		Environment string `json:"environment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Key == "" || req.Value == "" || req.Project == "" || req.Environment == "" {
		http.Error(w, `{"error":"key, value, project, and environment are required"}`, http.StatusBadRequest)
		return
	}

	secret, err := h.db.CreateSecret(req.Key, req.Value, req.Project, req.Environment)
	if err != nil {
		if errors.Is(err, database.ErrInvalidEnvironment) {
			http.Error(w, `{"error":"unknown project/environment pair: create it on the Environments page first"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"failed to create secret"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"key": req.Key, "project": req.Project, "environment": req.Environment})
	if err := h.audit.CreateEntry("secret.create", "admin", adminActor(r), "secret", secret.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": secret.ID})
}

func (h *AdminHandler) updateSecret(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Key         string `json:"key"`
		Value       string `json:"value"`
		Project     string `json:"project"`
		Environment string `json:"environment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Value == "" {
		existing, err := h.db.GetSecret(id)
		if err != nil {
			http.Error(w, `{"error":"failed to get secret"}`, http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
			return
		}
		req.Value = existing.Value
	}

	if err := h.db.UpdateSecret(id, req.Key, req.Value, req.Project, req.Environment); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
			return
		}
		if errors.Is(err, database.ErrInvalidEnvironment) {
			http.Error(w, `{"error":"unknown project/environment pair: create it on the Environments page first"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"failed to update secret"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"key": req.Key, "project": req.Project, "environment": req.Environment})
	if err := h.audit.CreateEntry("secret.update", "admin", adminActor(r), "secret", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeleteSecret(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"failed to delete secret"}`, http.StatusInternalServerError)
		return
	}

	if err := h.audit.CreateEntry("secret.delete", "admin", adminActor(r), "secret", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name              string `json:"name"`
		RepositoryPattern string `json:"repository_pattern"`
		RefPattern        string `json:"ref_pattern"`
		Project           string `json:"project"`
		Environment       string `json:"environment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.RepositoryPattern == "" || req.Project == "" || req.Environment == "" {
		http.Error(w, `{"error":"name, repository_pattern, project, and environment are required"}`, http.StatusBadRequest)
		return
	}
	if req.RefPattern == "" {
		req.RefPattern = "*"
	}

	policy, err := h.db.CreatePolicy(req.Name, req.RepositoryPattern, req.RefPattern, req.Project, req.Environment)
	if err != nil {
		if errors.Is(err, database.ErrInvalidEnvironment) {
			http.Error(w, `{"error":"unknown project/environment pair: create it on the Environments page first"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"failed to create policy"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"name": req.Name, "repository_pattern": req.RepositoryPattern, "project": req.Project, "environment": req.Environment})
	if err := h.audit.CreateEntry("policy.create", "admin", adminActor(r), "policy", policy.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": policy.ID})
}

func (h *AdminHandler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name              string `json:"name"`
		RepositoryPattern string `json:"repository_pattern"`
		RefPattern        string `json:"ref_pattern"`
		Project           string `json:"project"`
		Environment       string `json:"environment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.UpdatePolicy(id, req.Name, req.RepositoryPattern, req.RefPattern, req.Project, req.Environment); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"policy not found"}`, http.StatusNotFound)
			return
		}
		if errors.Is(err, database.ErrInvalidEnvironment) {
			http.Error(w, `{"error":"unknown project/environment pair: create it on the Environments page first"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"failed to update policy"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"name": req.Name, "repository_pattern": req.RepositoryPattern, "project": req.Project, "environment": req.Environment})
	if err := h.audit.CreateEntry("policy.update", "admin", adminActor(r), "policy", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeletePolicy(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"policy not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"failed to delete policy"}`, http.StatusInternalServerError)
		return
	}

	if err := h.audit.CreateEntry("policy.delete", "admin", adminActor(r), "policy", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Environments ---

func (h *AdminHandler) listEnvironments(w http.ResponseWriter, r *http.Request) {
	envs, err := h.db.ListEnvironments()
	if err != nil {
		http.Error(w, `{"error":"failed to list environments"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(envs)
}

func (h *AdminHandler) createEnvironment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project     string `json:"project"`
		Environment string `json:"environment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Project == "" || req.Environment == "" {
		http.Error(w, `{"error":"project and environment are required"}`, http.StatusBadRequest)
		return
	}

	env, err := h.db.CreateEnvironment(req.Project, req.Environment)
	if err != nil {
		http.Error(w, `{"error":"failed to create environment"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"project": req.Project, "environment": req.Environment})
	if err := h.audit.CreateEntry("environment.create", "admin", adminActor(r), "environment", env.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": env.ID})
}

func (h *AdminHandler) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	env, err := h.db.GetEnvironment(id)
	if err != nil {
		http.Error(w, `{"error":"failed to get environment"}`, http.StatusInternalServerError)
		return
	}
	if env == nil {
		http.Error(w, `{"error":"environment not found"}`, http.StatusNotFound)
		return
	}

	inUse, err := h.db.EnvironmentInUse(env.Project, env.Environment)
	if err != nil {
		http.Error(w, `{"error":"failed to check environment usage"}`, http.StatusInternalServerError)
		return
	}
	if inUse {
		http.Error(w, `{"error":"environment is still referenced by secrets or policies"}`, http.StatusConflict)
		return
	}

	if err := h.db.DeleteEnvironment(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"environment not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"failed to delete environment"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]string{"project": env.Project, "environment": env.Environment})
	if err := h.audit.CreateEntry("environment.delete", "admin", adminActor(r), "environment", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}
