package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

// maxRequestBodySize is the maximum allowed request body size (1 MB).
const maxRequestBodySize = 1 << 20

// requireJSON checks that the request Content-Type is application/json and
// limits the request body size. Returns false and writes an error response
// if the check fails.
func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" {
		http.Error(w, `{"error":"Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	return true
}

// validUUID returns true if s is a well-formed UUID.
func validUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

type AdminHandler struct {
	db    *database.DB
	audit *database.AuditDB
}

func NewAdminHandler(db *database.DB, audit *database.AuditDB) *AdminHandler {
	return &AdminHandler{db: db, audit: audit}
}

func (h *AdminHandler) Register(r chi.Router) {
	p := AdminPrefix + "/v1"

	// Nodes — unified create/read/update/delete for both secrets and groups.
	r.Get(p+"/nodes", h.listRootNodes)
	r.Post(p+"/nodes", h.createNode)
	r.Get(p+"/nodes/{id}", h.getNode)
	r.Put(p+"/nodes/{id}", h.updateNode)
	r.Delete(p+"/nodes/{id}", h.deleteNode)

	// Attached policies and precedence edges on a node.
	r.Get(p+"/nodes/{id}/policies", h.listNodePolicies)
	r.Post(p+"/nodes/{id}/policies", h.attachNodePolicy)
	r.Delete(p+"/nodes/{id}/policies/{policyID}", h.detachNodePolicy)
	r.Post(p+"/nodes/{id}/precedence", h.addNodePrecedence)
	r.Delete(p+"/nodes/{id}/precedence", h.removeNodePrecedence)

	// Policy CRUD.
	r.Get(p+"/policies", h.listPolicies)
	r.Post(p+"/policies", h.createPolicy)
	r.Get(p+"/policies/{id}", h.getPolicy)
	r.Put(p+"/policies/{id}", h.updatePolicy)
	r.Delete(p+"/policies/{id}", h.deletePolicy)
	r.Get(p+"/policies/{id}/nodes", h.listPolicyNodes)

	// Machine tokens — bearer credentials for non-Actions clients; each grants
	// a set of secret-tree nodes directly (no policy).
	r.Get(p+"/machine-tokens", h.listMachineTokens)
	r.Post(p+"/machine-tokens", h.createMachineToken)
	r.Put(p+"/machine-tokens/{id}", h.updateMachineToken)
	r.Delete(p+"/machine-tokens/{id}", h.deleteMachineToken)
	r.Post(p+"/machine-tokens/{id}/regenerate", h.regenerateMachineToken)
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

// nodeView is the JSON shape we return for a single node.
type nodeView struct {
	ID       string      `json:"id"`
	Kind     string      `json:"kind"`
	Name     string      `json:"name"`
	ParentID *string     `json:"parent_id"`
	Value    string      `json:"value,omitempty"`
	Children []*nodeView `json:"children,omitempty"`
}

// toView converts an ISecretNode tree to a JSON-serializable view. Secret
// values are plaintext — callers must not leak this to unauthorized clients.
func toView(n database.ISecretNode) *nodeView {
	v := &nodeView{
		ID:       n.ID(),
		Name:     n.Name(),
		ParentID: n.ParentID(),
	}
	switch node := n.(type) {
	case *database.Secret:
		v.Kind = "secret"
		v.Value = node.Value
	case *database.SecretGroup:
		v.Kind = "group"
		for _, c := range node.Children() {
			v.Children = append(v.Children, toView(c))
		}
	}
	return v
}

// --- Nodes ---

func (h *AdminHandler) listRootNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.db.LoadSubtree(nil)
	if err != nil {
		slog.Error("list root nodes failed", "error", err)
		http.Error(w, `{"error":"failed to list nodes"}`, http.StatusInternalServerError)
		return
	}
	views := make([]*nodeView, 0, len(nodes))
	for _, n := range nodes {
		views = append(views, toView(n))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views)
}

func (h *AdminHandler) getNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	sub, err := h.db.LoadSubtree(&id)
	if err != nil {
		slog.Error("get node failed", "error", err)
		http.Error(w, `{"error":"failed to get node"}`, http.StatusInternalServerError)
		return
	}
	if len(sub) == 0 {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toView(sub[0]))
}

func (h *AdminHandler) createNode(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	var req struct {
		Kind     string  `json:"kind"`
		ParentID *string `json:"parent_id"`
		Name     string  `json:"name"`
		Value    string  `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}
	if req.ParentID != nil && !validUUID(*req.ParentID) {
		http.Error(w, `{"error":"parent_id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	switch req.Kind {
	case "group":
		g, err := h.db.CreateGroup(req.ParentID, req.Name)
		if err != nil {
			slog.Error("create group failed", "error", err)
			http.Error(w, `{"error":"failed to create group"}`, http.StatusInternalServerError)
			return
		}
		details, _ := json.Marshal(map[string]any{"kind": "group", "name": req.Name, "parent_id": req.ParentID})
		if err := h.audit.CreateEntry("node.create", "admin", adminActor(r), "node", g.ID(), string(details)); err != nil {
			slog.Error("audit log failed", "error", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": g.ID()})
	case "secret":
		if req.Value == "" {
			http.Error(w, `{"error":"value is required for a secret"}`, http.StatusBadRequest)
			return
		}
		s, err := h.db.CreateSecret(req.ParentID, req.Name, req.Value)
		if err != nil {
			slog.Error("create secret failed", "error", err)
			http.Error(w, `{"error":"failed to create secret"}`, http.StatusInternalServerError)
			return
		}
		details, _ := json.Marshal(map[string]any{"kind": "secret", "name": req.Name, "parent_id": req.ParentID})
		if err := h.audit.CreateEntry("node.create", "admin", adminActor(r), "node", s.ID(), string(details)); err != nil {
			slog.Error("audit log failed", "error", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": s.ID()})
	default:
		http.Error(w, `{"error":"kind must be 'group' or 'secret'"}`, http.StatusBadRequest)
	}
}

func (h *AdminHandler) updateNode(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	var req struct {
		Name     *string `json:"name"`
		Value    *string `json:"value"`
		ParentID *string `json:"parent_id"`
		// Sentinel to distinguish "move to root" from "don't move".
		ChangeParent bool `json:"change_parent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name != nil {
		if err := h.db.RenameNode(id, *req.Name); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
				return
			}
			slog.Error("rename node failed", "error", err)
			http.Error(w, `{"error":"failed to rename node"}`, http.StatusInternalServerError)
			return
		}
	}
	if req.Value != nil {
		if err := h.db.UpdateSecretValue(id, *req.Value); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
				return
			}
			slog.Error("update value failed", "error", err)
			http.Error(w, `{"error":"failed to update value"}`, http.StatusInternalServerError)
			return
		}
	}
	if req.ChangeParent {
		if req.ParentID != nil && !validUUID(*req.ParentID) {
			http.Error(w, `{"error":"parent_id must be a valid UUID"}`, http.StatusBadRequest)
			return
		}
		if err := h.db.MoveNode(id, req.ParentID); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
				return
			}
			slog.Error("move node failed", "error", err)
			http.Error(w, `{"error":"failed to move node"}`, http.StatusInternalServerError)
			return
		}
	}

	details, _ := json.Marshal(map[string]any{"name": req.Name, "moved": req.ChangeParent})
	if err := h.audit.CreateEntry("node.update", "admin", adminActor(r), "node", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	if err := h.db.DeleteNode(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
			return
		}
		slog.Error("delete node failed", "error", err)
		http.Error(w, `{"error":"failed to delete node"}`, http.StatusInternalServerError)
		return
	}
	if err := h.audit.CreateEntry("node.delete", "admin", adminActor(r), "node", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Node-policy attachments and precedence ---

func (h *AdminHandler) listNodePolicies(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	policies, err := h.db.ListNodePolicies(id)
	if err != nil {
		slog.Error("list node policies failed", "error", err)
		http.Error(w, `{"error":"failed to list attached policies"}`, http.StatusInternalServerError)
		return
	}
	edges, err := h.db.ListNodePolicyPrecedence(id)
	if err != nil {
		slog.Error("list node precedence failed", "error", err)
		http.Error(w, `{"error":"failed to list precedence"}`, http.StatusInternalServerError)
		return
	}
	type edgeView struct {
		PolicyID    string `json:"policy_id"`
		DependsOnID string `json:"depends_on_id"`
	}
	edgeViews := make([]edgeView, 0, len(edges))
	for _, e := range edges {
		edgeViews = append(edgeViews, edgeView{PolicyID: e.PolicyID, DependsOnID: e.DependsOnID})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"policies":   policies,
		"precedence": edgeViews,
	})
}

func (h *AdminHandler) attachNodePolicy(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	var req struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if !validUUID(req.PolicyID) {
		http.Error(w, `{"error":"policy_id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	if err := h.db.AttachPolicy(id, req.PolicyID); err != nil {
		slog.Error("attach policy failed", "error", err)
		http.Error(w, `{"error":"failed to attach policy"}`, http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]string{"node_id": id, "policy_id": req.PolicyID})
	if err := h.audit.CreateEntry("policy.attach", "admin", adminActor(r), "node", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) detachNodePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policyID := chi.URLParam(r, "policyID")
	if !validUUID(id) || !validUUID(policyID) {
		http.Error(w, `{"error":"id and policyID must be valid UUIDs"}`, http.StatusBadRequest)
		return
	}
	if err := h.db.DetachPolicy(id, policyID); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"policy not attached to node"}`, http.StatusNotFound)
			return
		}
		slog.Error("detach policy failed", "error", err)
		http.Error(w, `{"error":"failed to detach policy"}`, http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]string{"node_id": id, "policy_id": policyID})
	if err := h.audit.CreateEntry("policy.detach", "admin", adminActor(r), "node", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) addNodePrecedence(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	var req struct {
		PolicyID    string `json:"policy_id"`
		DependsOnID string `json:"depends_on_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if !validUUID(req.PolicyID) || !validUUID(req.DependsOnID) {
		http.Error(w, `{"error":"policy_id and depends_on_id must be valid UUIDs"}`, http.StatusBadRequest)
		return
	}
	if err := h.db.AddPrecedence(id, req.PolicyID, req.DependsOnID); err != nil {
		slog.Error("add precedence failed", "error", err)
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) removeNodePrecedence(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.Error(w, `{"error":"id must be a valid UUID"}`, http.StatusBadRequest)
		return
	}
	var req struct {
		PolicyID    string `json:"policy_id"`
		DependsOnID string `json:"depends_on_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if err := h.db.RemovePrecedence(id, req.PolicyID, req.DependsOnID); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"edge not found"}`, http.StatusNotFound)
			return
		}
		slog.Error("remove precedence failed", "error", err)
		http.Error(w, `{"error":"failed to remove precedence"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Policies ---

// policyRequest is the JSON body for create/update policy endpoints.
// All three pattern lists may be empty, and an empty list of ANY kind is left
// empty — no kind defaults to ["*"]. An empty kind makes the policy match
// nothing for that kind (its inner JOIN in MatchingPolicyIDs yields no rows),
// so the policy is fail-closed: it grants no access until patterns are added,
// and "*" must be written explicitly. That keeps a blank ref/actor from
// silently widening a policy to "any ref / any actor" (a dangerous default on
// a policy that grants high-value secrets), and lets a placeholder policy be
// saved now and filled in later.
type policyRequest struct {
	Name               string   `json:"name"`
	RepositoryPatterns []string `json:"repository_patterns"`
	RefPatterns        []string `json:"ref_patterns"`
	ActorPatterns      []string `json:"actor_patterns"`
}

func (req *policyRequest) normalize() error {
	if err := database.ValidatePatterns(req.RepositoryPatterns); err != nil {
		return err
	}
	if err := database.ValidatePatterns(req.RefPatterns); err != nil {
		return err
	}
	if err := database.ValidatePatterns(req.ActorPatterns); err != nil {
		return err
	}
	return nil
}

func (h *AdminHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.db.ListPolicies()
	if err != nil {
		slog.Error("list policies failed", "error", err)
		http.Error(w, `{"error":"failed to list policies"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (h *AdminHandler) getPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policy, err := h.db.GetPolicy(id)
	if err != nil {
		slog.Error("get policy failed", "error", err)
		http.Error(w, `{"error":"failed to get policy"}`, http.StatusInternalServerError)
		return
	}
	if policy == nil {
		http.Error(w, `{"error":"policy not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func (h *AdminHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	var req policyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}
	if err := req.normalize(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	policy, err := h.db.CreatePolicy(req.Name, req.RepositoryPatterns, req.RefPatterns, req.ActorPatterns)
	if err != nil {
		slog.Error("create policy failed", "error", err)
		http.Error(w, `{"error":"failed to create policy"}`, http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]any{
		"name":                req.Name,
		"repository_patterns": req.RepositoryPatterns,
		"ref_patterns":        req.RefPatterns,
		"actor_patterns":      req.ActorPatterns,
	})
	if err := h.audit.CreateEntry("policy.create", "admin", adminActor(r), "policy", policy.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": policy.ID})
}

func (h *AdminHandler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	var req policyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if err := req.normalize(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := h.db.UpdatePolicy(id, req.Name, req.RepositoryPatterns, req.RefPatterns, req.ActorPatterns); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.Error(w, `{"error":"policy not found"}`, http.StatusNotFound)
			return
		}
		slog.Error("update policy failed", "error", err)
		http.Error(w, `{"error":"failed to update policy"}`, http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]any{
		"name":                req.Name,
		"repository_patterns": req.RepositoryPatterns,
		"ref_patterns":        req.RefPatterns,
		"actor_patterns":      req.ActorPatterns,
	})
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
		slog.Error("delete policy failed", "error", err)
		http.Error(w, `{"error":"failed to delete policy"}`, http.StatusInternalServerError)
		return
	}
	if err := h.audit.CreateEntry("policy.delete", "admin", adminActor(r), "policy", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) listPolicyNodes(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	nodes, err := h.db.ListNodesReferencingPolicy(id)
	if err != nil {
		slog.Error("list policy nodes failed", "error", err)
		http.Error(w, `{"error":"failed to list nodes"}`, http.StatusInternalServerError)
		return
	}
	views := make([]*nodeView, 0, len(nodes))
	for _, n := range nodes {
		views = append(views, toView(n))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views)
}
