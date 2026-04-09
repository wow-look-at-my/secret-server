package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/wow-look-at-my/secret-server/internal/auth"
	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/secret-server/internal/templates"
)

// parsePatternLines splits a textarea value into a slice of trimmed,
// non-empty lines — one glob pattern per line.
func parsePatternLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

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

	// Unified secret-tree browser.
	r.Get(p+"/secrets", h.browseTree)
	r.Get(p+"/secrets/new", h.newNodeForm)
	r.Get(p+"/secrets/{id}", h.viewNode)
	r.Get(p+"/secrets/{id}/edit", h.editNodeForm)
	r.Post(p+"/secrets", h.createNodeForm)
	r.Post(p+"/secrets/{id}", h.updateNodeForm)
	r.Post(p+"/secrets/{id}/delete", h.deleteNodeForm)
	r.Post(p+"/secrets/{id}/policies/attach", h.attachPolicyForm)
	r.Post(p+"/secrets/{id}/policies/{policyID}/detach", h.detachPolicyForm)

	// Policies.
	r.Get(p+"/policies", h.listPolicies)
	r.Get(p+"/policies/new", h.newPolicy)
	r.Get(p+"/policies/{id}/edit", h.editPolicy)
	r.Post(p+"/policies", h.createPolicy)
	r.Post(p+"/policies/{id}", h.updatePolicy)
	r.Post(p+"/policies/{id}/delete", h.deletePolicyForm)

	r.Get(p+"/audit", h.auditLog)
	r.Get(p+"/style.css", h.tmpl.ServeCSS)

	r.Get(p, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p+"/", http.StatusFound)
	})
	// Catch-all: redirect unknown /admin/* paths to /admin/.
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

// nodeTemplateView is the shape the tree and node templates consume. It is
// built from the ISecretNode domain types with per-node
// "HasEffectivePolicies" flags computed via a single downward walk so the
// templates can flag unreachable nodes without any additional lookups.
type nodeTemplateView struct {
	ID                   string
	Kind                 string // "secret" or "group"
	Name                 string
	Value                string
	HasEffectivePolicies bool
	Children             []*nodeTemplateView
	ParentID             *string
}

// buildTreeView walks a slice of root ISecretNodes and produces a tree of
// nodeTemplateViews. HasEffectivePolicies on a node is true iff that node
// or any of its ancestors has a directly-attached policy.
func buildTreeView(roots []database.ISecretNode, attached map[string]bool) []*nodeTemplateView {
	var visit func(n database.ISecretNode, ancestorHas bool) *nodeTemplateView
	visit = func(n database.ISecretNode, ancestorHas bool) *nodeTemplateView {
		effective := ancestorHas || attached[n.ID()]
		v := &nodeTemplateView{
			ID:                   n.ID(),
			Name:                 n.Name(),
			HasEffectivePolicies: effective,
			ParentID:             n.ParentID(),
		}
		switch node := n.(type) {
		case *database.Secret:
			v.Kind = "secret"
			v.Value = node.Value
		case *database.SecretGroup:
			v.Kind = "group"
			for _, c := range node.Children() {
				v.Children = append(v.Children, visit(c, effective))
			}
		}
		return v
	}
	out := make([]*nodeTemplateView, 0, len(roots))
	for _, r := range roots {
		out = append(out, visit(r, false))
	}
	return out
}

// collectAttachedNodeIDs returns the set of node IDs that have at least one
// policy attached directly. For the node counts in a self-hosted server this
// is a cheap scan — one COUNT() per node. If it ever becomes a bottleneck
// we can replace it with a single GROUP BY query.
func (h *UIHandler) collectAttachedNodeIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := h.db.Q().ListAllNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		cnt, err := h.db.Q().CountAttachedPoliciesForNode(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			out[r.ID] = true
		}
	}
	return out, nil
}

// countUnreachableNodes counts the nodes whose effective policy set is empty
// (no attachments on this node or any ancestor). Used by the dashboard for
// its "N nodes have no effective policies" summary line.
func countUnreachableNodes(views []*nodeTemplateView) int {
	total := 0
	var walk func(*nodeTemplateView)
	walk = func(v *nodeTemplateView) {
		if !v.HasEffectivePolicies {
			total++
		}
		for _, c := range v.Children {
			walk(c)
		}
	}
	for _, v := range views {
		walk(v)
	}
	return total
}

// countNodeKinds counts groups and secrets in the full tree. Used by the
// dashboard stats cards.
func countNodeKinds(views []*nodeTemplateView) (groups, secrets int) {
	var walk func(*nodeTemplateView)
	walk = func(v *nodeTemplateView) {
		if v.Kind == "group" {
			groups++
		} else {
			secrets++
		}
		for _, c := range v.Children {
			walk(c)
		}
	}
	for _, v := range views {
		walk(v)
	}
	return groups, secrets
}

func (h *UIHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roots, err := h.db.LoadSubtree(nil)
	if err != nil {
		slog.Error("dashboard load failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	attached, err := h.collectAttachedNodeIDs(ctx)
	if err != nil {
		slog.Error("collect attached nodes failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	views := buildTreeView(roots, attached)
	groups, secrets := countNodeKinds(views)
	unreachable := countUnreachableNodes(views)

	policyCount, err := h.db.Q().CountPolicies(ctx)
	if err != nil {
		slog.Error("count policies failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.tmpl.Render(w, r, "dashboard.html", map[string]any{
		"TotalGroups":       groups,
		"TotalSecrets":      secrets,
		"TotalPolicies":     policyCount,
		"UnreachableCount":  unreachable,
		"Roots":             views,
	})
}

// base64JSONStructure tries to base64-decode a value and parse it as JSON.
// If the value is a base64-encoded JSON object, returns a redacted version
// showing only top-level keys with "..." as values. Returns empty otherwise.
func base64JSONStructure(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
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

// --- Node tree browsing ---

func (h *UIHandler) browseTree(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roots, err := h.db.LoadSubtree(nil)
	if err != nil {
		slog.Error("browse tree failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	attached, err := h.collectAttachedNodeIDs(ctx)
	if err != nil {
		slog.Error("collect attached nodes failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	views := buildTreeView(roots, attached)
	h.tmpl.Render(w, r, "secrets_browse.html", map[string]any{
		"Roots": views,
	})
}

// viewNode shows a single node: its breadcrumb, its direct children (if a
// group), and its attached policies.
func (h *UIHandler) viewNode(w http.ResponseWriter, r *http.Request) {
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
	// Load subtree anchored at this node so children are populated.
	sub, err := h.db.LoadSubtree(&id)
	if err != nil {
		slog.Error("load subtree failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	attached, err := h.collectAttachedNodeIDs(ctx)
	if err != nil {
		slog.Error("collect attached nodes failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// Compute ancestor-has-policies by walking up from this node.
	ancestorHas, err := h.anyAncestorHasPolicy(ctx, node.ParentID(), attached)
	if err != nil {
		slog.Error("ancestor walk failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	views := buildTreeView(sub, attached)
	for _, v := range views {
		if ancestorHas {
			markEffective(v)
		}
	}

	policies, err := h.db.ListNodePolicies(id)
	if err != nil {
		slog.Error("list node policies failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	allPolicies, err := h.db.ListPolicies()
	if err != nil {
		slog.Error("list policies failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	attachedIDs := make(map[string]bool, len(policies))
	for _, p := range policies {
		attachedIDs[p.ID] = true
	}
	var available []database.Policy
	for _, p := range allPolicies {
		if !attachedIDs[p.ID] {
			available = append(available, p)
		}
	}

	crumbs, err := h.buildBreadcrumbs(ctx, node)
	if err != nil {
		slog.Error("build breadcrumbs failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Node":              views[0],
		"AttachedPolicies":  policies,
		"AvailablePolicies": available,
		"Breadcrumbs":       crumbs,
	}
	h.tmpl.Render(w, r, "node_view.html", data)
}

// anyAncestorHasPolicy walks up the parent chain from parentID looking for
// any ancestor with an attached policy.
func (h *UIHandler) anyAncestorHasPolicy(ctx context.Context, parentID *string, attached map[string]bool) (bool, error) {
	for parentID != nil {
		if attached[*parentID] {
			return true, nil
		}
		row, err := h.db.Q().GetSecretNode(ctx, *parentID)
		if err != nil {
			return false, err
		}
		if row.ParentID.Valid {
			s := row.ParentID.String
			parentID = &s
		} else {
			parentID = nil
		}
	}
	return false, nil
}

// markEffective sets HasEffectivePolicies on the given view and all its
// descendants (used when an ancestor outside this subtree has a policy).
func markEffective(v *nodeTemplateView) {
	v.HasEffectivePolicies = true
	for _, c := range v.Children {
		markEffective(c)
	}
}

// buildBreadcrumbs walks up from a node to the root, returning a slice of
// views ordered root-first.
func (h *UIHandler) buildBreadcrumbs(ctx context.Context, node database.ISecretNode) ([]*nodeTemplateView, error) {
	var crumbs []*nodeTemplateView
	parentID := node.ParentID()
	for parentID != nil {
		row, err := h.db.Q().GetSecretNode(ctx, *parentID)
		if err != nil {
			return nil, err
		}
		v := &nodeTemplateView{
			ID:   row.ID,
			Name: row.Name,
			Kind: row.Kind,
		}
		crumbs = append([]*nodeTemplateView{v}, crumbs...)
		if row.ParentID.Valid {
			s := row.ParentID.String
			parentID = &s
		} else {
			parentID = nil
		}
	}
	return crumbs, nil
}

// --- Node create / edit / delete forms ---

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
	if s := base64JSONStructure(value); s != "" {
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

// formParentID parses the parent_id form field. Empty string or "" means
// root-level (return nil).
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

	// parent_id is present on the form only when the user explicitly wants
	// to move the node. Detect via a hidden "move" field.
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

// --- Policies ---

// policyListView pairs a policy with the count of nodes it's attached to.
type policyListView struct {
	database.Policy
	AttachedNodeCount int64
}

func (h *UIHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policies, err := h.db.ListPolicies()
	if err != nil {
		slog.Error("list policies failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	views := make([]policyListView, 0, len(policies))
	for _, p := range policies {
		cnt, err := h.db.Q().CountNodesReferencingPolicy(ctx, p.ID)
		if err != nil {
			slog.Error("count nodes referencing policy failed", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		views = append(views, policyListView{Policy: p, AttachedNodeCount: cnt})
	}
	h.tmpl.Render(w, r, "policies_list.html", views)
}

func (h *UIHandler) newPolicy(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, r, "policy_form.html", map[string]any{
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
	h.tmpl.Render(w, r, "policy_form.html", map[string]any{
		"IsNew":  false,
		"Policy": policy,
	})
}

// parsePolicyPatternsForm extracts and validates the three pattern lists
// from an access-policy form submission. Empty ref/actor lists default to
// ["*"] so the common "allow any ref / any actor" case still works without
// the user typing it; repository patterns must be explicit.
func parsePolicyPatternsForm(r *http.Request) (repo, ref, actor []string, err error) {
	repo = parsePatternLines(r.FormValue("repository_patterns"))
	ref = parsePatternLines(r.FormValue("ref_patterns"))
	actor = parsePatternLines(r.FormValue("actor_patterns"))
	if len(repo) == 0 {
		return nil, nil, nil, fmt.Errorf("at least one repository pattern is required")
	}
	if len(ref) == 0 {
		ref = []string{"*"}
	}
	if len(actor) == 0 {
		actor = []string{"*"}
	}
	for _, list := range [][]string{repo, ref, actor} {
		if err := database.ValidatePatterns(list); err != nil {
			return nil, nil, nil, err
		}
	}
	return repo, ref, actor, nil
}

func (h *UIHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	repoPatterns, refPatterns, actorPatterns, err := parsePolicyPatternsForm(r)
	if err != nil {
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew": true,
			"Error": err.Error(),
			"Form":  r.Form,
		})
		return
	}
	policy, err := h.db.CreatePolicy(r.FormValue("name"), repoPatterns, refPatterns, actorPatterns)
	if err != nil {
		slog.Error("create policy failed", "error", err)
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew": true,
			"Error": "Failed to create policy. Check server logs.",
			"Form":  r.Form,
		})
		return
	}
	details, _ := json.Marshal(map[string]any{
		"name":                r.FormValue("name"),
		"repository_patterns": repoPatterns,
		"ref_patterns":        refPatterns,
		"actor_patterns":      actorPatterns,
	})
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
	repoPatterns, refPatterns, actorPatterns, err := parsePolicyPatternsForm(r)
	if err != nil {
		existing, _ := h.db.GetPolicy(id)
		h.tmpl.Render(w, r, "policy_form.html", map[string]any{
			"IsNew":  false,
			"Policy": existing,
			"Error":  err.Error(),
			"Form":   r.Form,
		})
		return
	}
	if err := h.db.UpdatePolicy(id, r.FormValue("name"), repoPatterns, refPatterns, actorPatterns); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("update policy failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]any{
		"name":                r.FormValue("name"),
		"repository_patterns": repoPatterns,
		"ref_patterns":        refPatterns,
		"actor_patterns":      actorPatterns,
	})
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
		"Entries":  toAuditViews(entries),
		"Page":     page,
		"HasNext":  offset+perPage < total,
		"HasPrev":  page > 1,
		"NextPage": page + 1,
		"PrevPage": page - 1,
	})
}
