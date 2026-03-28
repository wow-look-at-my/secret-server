package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/wow-look-at-my/secret-server/internal/database"
)

type AdminHandler struct {
	db *database.DB
}

func NewAdminHandler(db *database.DB) *AdminHandler {
	return &AdminHandler{db: db}
}

func (h *AdminHandler) Register(mux *http.ServeMux) {
	p := AdminPrefix + "/v1"
	mux.HandleFunc("POST "+p+"/secrets", h.createSecret)
	mux.HandleFunc("PUT "+p+"/secrets/{id}", h.updateSecret)
	mux.HandleFunc("DELETE "+p+"/secrets/{id}", h.deleteSecret)
	mux.HandleFunc("POST "+p+"/policies", h.createPolicy)
	mux.HandleFunc("PUT "+p+"/policies/{id}", h.updatePolicy)
	mux.HandleFunc("DELETE "+p+"/policies/{id}", h.deletePolicy)
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
		http.Error(w, `{"error":"failed to create secret"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": secret.ID})
}

func (h *AdminHandler) updateSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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

	if err := h.db.UpdateSecret(id, req.Key, req.Value, req.Project, req.Environment); err != nil {
		http.Error(w, `{"error":"failed to update secret"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.db.DeleteSecret(id); err != nil {
		http.Error(w, `{"error":"failed to delete secret"}`, http.StatusInternalServerError)
		return
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
		http.Error(w, `{"error":"failed to create policy"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": policy.ID})
}

func (h *AdminHandler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
		http.Error(w, `{"error":"failed to update policy"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.db.DeletePolicy(id); err != nil {
		http.Error(w, `{"error":"failed to delete policy"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
