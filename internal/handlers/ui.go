package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
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

	// Unified secret-tree browser. Node form handlers live in ui_nodes.go.
	r.Get(p+"/secrets", h.browseTree)
	r.Get(p+"/secrets/new", h.newNodeForm)
	r.Get(p+"/secrets/{id}", h.viewNode)
	r.Get(p+"/secrets/{id}/edit", h.editNodeForm)
	r.Post(p+"/secrets", h.createNodeForm)
	r.Post(p+"/secrets/{id}", h.updateNodeForm)
	r.Post(p+"/secrets/{id}/delete", h.deleteNodeForm)
	r.Post(p+"/secrets/{id}/policies/attach", h.attachPolicyForm)
	r.Post(p+"/secrets/{id}/policies/{policyID}/detach", h.detachPolicyForm)

	// Policies. Handlers live in ui_policies.go.
	r.Get(p+"/policies", h.listPolicies)
	r.Get(p+"/policies/new", h.newPolicy)
	r.Get(p+"/policies/{id}/edit", h.editPolicy)
	r.Post(p+"/policies", h.createPolicy)
	r.Post(p+"/policies/{id}", h.updatePolicy)
	r.Post(p+"/policies/{id}/delete", h.deletePolicyForm)

	// Machine tokens. Handlers live in ui_machine_tokens.go.
	r.Get(p+"/machine-tokens", h.listMachineTokens)
	r.Get(p+"/machine-tokens/new", h.newMachineToken)
	r.Post(p+"/machine-tokens", h.createMachineToken)
	r.Post(p+"/machine-tokens/{id}/delete", h.deleteMachineTokenForm)

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
// (no attachments on this node or any ancestor). Used by the dashboard.
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
		"TotalGroups":      groups,
		"TotalSecrets":     secrets,
		"TotalPolicies":    policyCount,
		"UnreachableCount": unreachable,
		"Roots":            views,
	})
}

// base64JSONDecode tries to base64-decode a value and parse it as JSON.
// If the value is a base64-encoded JSON object, it returns pretty-printed JSON.
// Returns empty string otherwise.
func base64JSONDecode(value string) string {
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
	out, err := json.MarshalIndent(obj, "", "  ")
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
// group), and its attached policies with an attach-policy form for any
// unattached policies.
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
	if ancestorHas {
		for _, v := range views {
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

	h.tmpl.Render(w, r, "node_view.html", map[string]any{
		"Node":              views[0],
		"AttachedPolicies":  policies,
		"AvailablePolicies": available,
		"Breadcrumbs":       crumbs,
	})
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
