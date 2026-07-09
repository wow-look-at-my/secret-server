package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

// Machine-token admin API handlers. Routes are registered in AdminHandler.Register.
// A machine token attaches directly to secret-tree nodes and vends those secrets
// (a group grants its subtree) to non-Actions clients — no policy.

// machineTokenView is the JSON shape for a machine token in the admin API: the
// token metadata plus the secret-tree nodes it grants.
type machineTokenView struct {
	database.MachineToken
	Nodes []database.TokenNode `json:"nodes"`
}

// machineTokenRequest is the JSON body for create/update. A token grants the
// union of its direct node_ids (a leaf grants that secret, a group its subtree)
// and its optional bound policy_id (empty = no policy).
type machineTokenRequest struct {
	Name     string   `json:"name"`
	PolicyID string   `json:"policy_id"`
	NodeIDs  []string `json:"node_ids"`
}

// validNodeIDs reports whether every id is a well-formed UUID.
func validNodeIDs(ids []string) bool {
	for _, id := range ids {
		if !validUUID(id) {
			return false
		}
	}
	return true
}

// optionalPolicyID validates the request's policy_id and returns it as an
// optional pointer (nil when empty). ok is false on a malformed (non-UUID) id.
func (req machineTokenRequest) optionalPolicyID() (policy *string, ok bool) {
	if req.PolicyID == "" {
		return nil, true
	}
	if !validUUID(req.PolicyID) {
		return nil, false
	}
	id := req.PolicyID
	return &id, true
}

func (h *AdminHandler) listMachineTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.db.ListMachineTokens()
	if err != nil {
		slog.Error("list machine tokens failed", "error", err)
		http.Error(w, `{"error":"failed to list machine tokens"}`, http.StatusInternalServerError)
		return
	}
	views := make([]machineTokenView, 0, len(tokens))
	for _, t := range tokens {
		nodes, err := h.db.ListTokenNodes(t.ID)
		if err != nil {
			slog.Error("list token nodes failed", "error", err, "token_id", t.ID)
			http.Error(w, `{"error":"failed to list machine tokens"}`, http.StatusInternalServerError)
			return
		}
		views = append(views, machineTokenView{MachineToken: t, Nodes: nodes})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views)
}

func (h *AdminHandler) createMachineToken(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	var req machineTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}
	if !validNodeIDs(req.NodeIDs) {
		http.Error(w, `{"error":"node_ids must be valid UUIDs"}`, http.StatusBadRequest)
		return
	}
	policyID, ok := req.optionalPolicyID()
	if !ok {
		http.Error(w, `{"error":"policy_id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}

	token, rec, err := h.db.CreateMachineToken(req.Name, policyID, req.NodeIDs)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"the policy or one or more secrets were not found"}`, http.StatusBadRequest)
			return
		}
		slog.Error("create machine token failed", "error", err)
		http.Error(w, `{"error":"failed to create machine token"}`, http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]any{"name": req.Name, "policy_id": req.PolicyID, "node_count": len(req.NodeIDs)})
	if err := h.audit.CreateEntry("machine_token.create", "admin", adminActor(r), "machine_token", rec.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	// The plaintext token is returned exactly once — only its hash is stored.
	json.NewEncoder(w).Encode(map[string]string{"id": rec.ID, "token": token})
}

func (h *AdminHandler) updateMachineToken(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	var req machineTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if !validNodeIDs(req.NodeIDs) {
		http.Error(w, `{"error":"node_ids must be valid UUIDs"}`, http.StatusBadRequest)
		return
	}
	policyID, ok := req.optionalPolicyID()
	if !ok {
		http.Error(w, `{"error":"policy_id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	tok, err := h.db.GetMachineToken(id)
	if err != nil {
		slog.Error("look up machine token failed", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if tok == nil {
		http.Error(w, `{"error":"machine token not found"}`, http.StatusNotFound)
		return
	}
	if err := h.db.UpdateMachineToken(id, policyID, req.NodeIDs); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"the policy or one or more secrets were not found"}`, http.StatusBadRequest)
			return
		}
		slog.Error("update machine token failed", "error", err)
		http.Error(w, `{"error":"failed to update machine token"}`, http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]any{"policy_id": req.PolicyID, "node_count": len(req.NodeIDs)})
	if err := h.audit.CreateEntry("machine_token.update", "admin", adminActor(r), "machine_token", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// regenerateMachineToken mints a fresh token value for an existing token,
// keeping its name, bound policy, and node attachments. The old value stops
// working immediately.
func (h *AdminHandler) regenerateMachineToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token, err := h.db.RegenerateMachineToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"machine token not found"}`, http.StatusNotFound)
			return
		}
		slog.Error("regenerate machine token failed", "error", err)
		http.Error(w, `{"error":"failed to regenerate machine token"}`, http.StatusInternalServerError)
		return
	}

	if err := h.audit.CreateEntry("machine_token.regenerate", "admin", adminActor(r), "machine_token", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	// The plaintext token is returned exactly once — only its hash is stored.
	json.NewEncoder(w).Encode(map[string]string{"id": id, "token": token})
}

func (h *AdminHandler) deleteMachineToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeleteMachineToken(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"machine token not found"}`, http.StatusNotFound)
			return
		}
		slog.Error("delete machine token failed", "error", err)
		http.Error(w, `{"error":"failed to delete machine token"}`, http.StatusInternalServerError)
		return
	}

	if err := h.audit.CreateEntry("machine_token.delete", "admin", adminActor(r), "machine_token", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}
