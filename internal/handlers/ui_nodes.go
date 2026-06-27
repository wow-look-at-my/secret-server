package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

// --- Node create / edit / delete / policy-attach forms ---

func (h *UIHandler) newNodeForm(w http.ResponseWriter, r *http.Request) {
	parentID := r.URL.Query().Get("parent")
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "secret"
	}
	parents, err := h.loadGroupList(r.Context())
	if err != nil {
		slog.Error("load group list failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "node_form.html", map[string]any{
		"IsNew":    true,
		"Kind":     kind,
		"ParentID": parentID,
		"Groups":   parents,
	})
}

func (h *UIHandler) editNodeForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.NotFound(w, r)
		return
	}
	node, err := h.db.GetNode(id)
	if err != nil {
		slog.Error("get node failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if node == nil {
		http.NotFound(w, r)
		return
	}
	parents, err := h.loadGroupList(ctx)
	if err != nil {
		slog.Error("load group list failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	kind := "group"
	value := ""
	if s, ok := node.(*database.Secret); ok {
		kind = "secret"
		value = s.Value
	}
	parentID := ""
	if p := node.ParentID(); p != nil {
		parentID = *p
	}
	data := map[string]any{
		"IsNew":    false,
		"Kind":     kind,
		"Node":     node,
		"NodeID":   node.ID(),
		"Name":     node.Name(),
		"Value":    value,
		"ParentID": parentID,
		"Groups":   parents,
	}
	if s := base64JSONDecode(value); s != "" {
		data["JSONStructure"] = s
	}
	h.tmpl.Render(w, r, "node_form.html", data)
}

// loadGroupList returns all groups as flat (ID, Name) pairs for populating
// parent-select dropdowns in the new/edit form.
func (h *UIHandler) loadGroupList(ctx context.Context) ([]groupOption, error) {
	rows, err := h.db.Q().ListAllNodes(ctx)
	if err != nil {
		return nil, err
	}
	var out []groupOption
	for _, r := range rows {
		if r.Kind == "group" {
			out = append(out, groupOption{ID: r.ID, Name: r.Name})
		}
	}
	return out, nil
}

type groupOption struct {
	ID   string
	Name string
}

func (h *UIHandler) createNodeForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	kind := r.FormValue("kind")
	name := r.FormValue("name")
	value := r.FormValue("value")
	parentID := formParentID(r)

	if name == "" {
		h.renderNewFormError(w, r, kind, "Name is required.", parentID)
		return
	}

	switch kind {
	case "group":
		if _, err := h.db.CreateGroup(parentID, name); err != nil {
			slog.Error("create group failed", "error", err)
			h.renderNewFormError(w, r, kind, "Failed to create group. Check server logs.", parentID)
			return
		}
	case "secret":
		if value == "" {
			h.renderNewFormError(w, r, kind, "Value is required for a secret.", parentID)
			return
		}
		if _, err := h.db.CreateSecret(parentID, name, value); err != nil {
			slog.Error("create secret failed", "error", err)
			h.renderNewFormError(w, r, kind, "Failed to create secret. Check server logs.", parentID)
			return
		}
	default:
		http.Error(w, "invalid kind", http.StatusBadRequest)
		return
	}

	details, _ := json.Marshal(map[string]any{"kind": kind, "name": name, "parent_id": parentID})
	if err := h.audit.CreateEntry("node.create", "admin", uiActor(r), "node", "", string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) renderNewFormError(w http.ResponseWriter, r *http.Request, kind, msg string, parentID *string) {
	groups, _ := h.loadGroupList(r.Context())
	p := ""
	if parentID != nil {
		p = *parentID
	}
	h.tmpl.Render(w, r, "node_form.html", map[string]any{
		"IsNew":    true,
		"Kind":     kind,
		"ParentID": p,
		"Groups":   groups,
		"Error":    msg,
		"Form":     r.Form,
	})
}

// formParentID parses the parent_id form field. An empty field means "no
// parent change" / "root level" and returns nil.
func formParentID(r *http.Request) *string {
	p := strings.TrimSpace(r.FormValue("parent_id"))
	if p == "" {
		return nil
	}
	if _, err := uuid.Parse(p); err != nil {
		return nil
	}
	return &p
}

func (h *UIHandler) updateNodeForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	value := r.FormValue("value")

	if name != "" {
		if err := h.db.RenameNode(id, name); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			slog.Error("rename node failed", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	if value != "" {
		if err := h.db.UpdateSecretValue(id, value); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			slog.Error("update secret value failed", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// parent_id is applied only when the user explicitly ticks the
	// "change parent" checkbox. Without the sentinel the form silently
	// moving nodes on every edit would be too easy to do by accident.
	if r.FormValue("move") == "1" {
		parentID := formParentID(r)
		if err := h.db.MoveNode(id, parentID); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			slog.Error("move node failed", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	details, _ := json.Marshal(map[string]any{"name": name, "value_changed": value != ""})
	if err := h.audit.CreateEntry("node.update", "admin", uiActor(r), "node", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	http.Redirect(w, r, AdminPrefix+"/secrets/"+id, http.StatusSeeOther)
}

func (h *UIHandler) deleteNodeForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.NotFound(w, r)
		return
	}
	if err := h.db.DeleteNode(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("delete node failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := h.audit.CreateEntry("node.delete", "admin", uiActor(r), "node", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/secrets", http.StatusSeeOther)
}

func (h *UIHandler) attachPolicyForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	id := chi.URLParam(r, "id")
	if !validUUID(id) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	policyID := r.FormValue("policy_id")
	if !validUUID(policyID) {
		http.Error(w, "invalid policy id", http.StatusBadRequest)
		return
	}
	if err := h.db.AttachPolicy(id, policyID); err != nil {
		slog.Error("attach policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]string{"node_id": id, "policy_id": policyID})
	if err := h.audit.CreateEntry("policy.attach", "admin", uiActor(r), "node", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/secrets/"+id, http.StatusSeeOther)
}

func (h *UIHandler) detachPolicyForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policyID := chi.URLParam(r, "policyID")
	if !validUUID(id) || !validUUID(policyID) {
		http.NotFound(w, r)
		return
	}
	if err := h.db.DetachPolicy(id, policyID); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("detach policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]string{"node_id": id, "policy_id": policyID})
	if err := h.audit.CreateEntry("policy.detach", "admin", uiActor(r), "node", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/secrets/"+id, http.StatusSeeOther)
}
