package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

// Machine-token admin UI pages. Routes are registered in UIHandler.Register.
// A machine token grants secrets two ways, either or both: by attaching directly
// to secret-tree nodes, and/or via an optional bound policy. It vends the union
// to non-Actions clients. See internal/database/machine_tokens.go.

// nodeOption is one selectable secret-tree node in the token form's picker.
type nodeOption struct {
	ID       string
	Kind     string // "secret" or "group"
	Path     string // human path, e.g. "prod / api / GITHUB_APP_PRIVATE_KEY"
	Selected bool
}

// machineTokenListView pairs a token with the nodes it grants directly, for the
// list page (the bound policy, if any, is on the embedded MachineToken).
type machineTokenListView struct {
	database.MachineToken
	Nodes []database.TokenNode
}

// flattenNodeOptions walks the secret tree depth-first into a flat option list,
// labelling each node with its full path and marking the ones in selected. A
// group is listed before its descendants so the operator can grant a whole
// subtree by checking the group, or pick individual leaves.
func flattenNodeOptions(nodes []database.ISecretNode, prefix string, selected map[string]bool, out *[]nodeOption) {
	for _, n := range nodes {
		path := n.Name()
		if prefix != "" {
			path = prefix + " / " + n.Name()
		}
		switch node := n.(type) {
		case *database.SecretGroup:
			*out = append(*out, nodeOption{ID: node.ID(), Kind: "group", Path: path, Selected: selected[node.ID()]})
			flattenNodeOptions(node.Children(), path, selected, out)
		case *database.Secret:
			*out = append(*out, nodeOption{ID: node.ID(), Kind: "secret", Path: path, Selected: selected[node.ID()]})
		}
	}
}

// nodeOptions loads the whole secret tree as a flat, path-labelled option list,
// pre-selecting the ids in selected (nil = none).
func (h *UIHandler) nodeOptions(selected map[string]bool) ([]nodeOption, error) {
	roots, err := h.db.LoadSubtree(nil)
	if err != nil {
		return nil, err
	}
	if selected == nil {
		selected = map[string]bool{}
	}
	var out []nodeOption
	flattenNodeOptions(roots, "", selected, &out)
	return out, nil
}

// selectedSet turns a slice of node IDs into a lookup set.
func selectedSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// formPolicyID reads the optional policy_id form field as a pointer (nil when
// the operator chose "no policy").
func formPolicyID(r *http.Request) *string {
	id := r.FormValue("policy_id")
	if id == "" {
		return nil
	}
	return &id
}

// derefString returns the pointed-at string, or "" for nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (h *UIHandler) listMachineTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.db.ListMachineTokens()
	if err != nil {
		slog.Error("list machine tokens failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	views := make([]machineTokenListView, 0, len(tokens))
	for _, t := range tokens {
		nodes, err := h.db.ListTokenNodes(t.ID)
		if err != nil {
			slog.Error("list token nodes failed", "error", err, "token_id", t.ID)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		views = append(views, machineTokenListView{MachineToken: t, Nodes: nodes})
	}
	h.tmpl.Render(w, r, "machine_tokens_list.html", map[string]any{"Tokens": views})
}

// renderTokenForm renders the create/edit form with the node picker and policy
// dropdown populated. selectedPolicy pre-selects a policy in the dropdown.
func (h *UIHandler) renderTokenForm(w http.ResponseWriter, r *http.Request, data map[string]any, selectedNodes map[string]bool, selectedPolicy string) {
	opts, err := h.nodeOptions(selectedNodes)
	if err != nil {
		slog.Error("load nodes for machine token form failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	policies, err := h.db.ListPolicies()
	if err != nil {
		slog.Error("list policies for machine token form failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data["Nodes"] = opts
	data["Policies"] = policies
	data["SelectedPolicy"] = selectedPolicy
	h.tmpl.Render(w, r, "machine_token_form.html", data)
}

func (h *UIHandler) newMachineToken(w http.ResponseWriter, r *http.Request) {
	h.renderTokenForm(w, r, map[string]any{"IsNew": true}, nil, "")
}

func (h *UIHandler) createMachineToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	nodeIDs := r.Form["node_ids"]
	policyID := formPolicyID(r)
	canAttest := r.FormValue("can_attest_github_pushes") == "on"

	renderErr := func(msg string) {
		h.renderTokenForm(w, r, map[string]any{"IsNew": true, "Error": msg, "Form": r.Form},
			selectedSet(nodeIDs), derefString(policyID))
	}

	if name == "" {
		renderErr("Name is required.")
		return
	}
	// A token may be created with nothing attached — it simply vends nothing
	// until secrets and/or a policy are added later.

	token, rec, err := h.db.CreateMachineToken(name, policyID, nodeIDs)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			renderErr("The selected policy or secret no longer exists. Reload and try again.")
			return
		}
		slog.Error("create machine token failed", "error", err)
		renderErr("Failed to create machine token. Check server logs for details.")
		return
	}
	if err := h.db.SetMachineTokenGitHubAttestation(r.Context(), rec.ID, canAttest); err != nil {
		_ = h.db.DeleteMachineToken(rec.ID)
		slog.Error("set machine token GitHub attestation permission failed", "error", err)
		renderErr("Failed to create machine token. Check server logs for details.")
		return
	}

	details, _ := json.Marshal(map[string]any{
		"name": name, "policy_id": derefString(policyID),
		"node_count":               len(nodeIDs),
		"can_attest_github_pushes": canAttest,
	})
	if err := h.audit.CreateEntry("machine_token.create", "admin", uiActor(r), "machine_token", rec.ID, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	// Show the token exactly once — it is not recoverable later.
	h.tmpl.Render(w, r, "machine_token_created.html", map[string]any{
		"Token": token,
		"Name":  name,
	})
}

func (h *UIHandler) editMachineToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tok, err := h.db.GetMachineToken(id)
	if err != nil {
		slog.Error("get machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if tok == nil {
		http.NotFound(w, r)
		return
	}
	attached, err := h.db.ListTokenNodes(id)
	if err != nil {
		slog.Error("list token nodes failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	sel := make(map[string]bool, len(attached))
	for _, n := range attached {
		sel[n.ID] = true
	}
	h.renderTokenForm(w, r, map[string]any{"IsNew": false, "Token": tok}, sel, derefString(tok.PolicyID))
}

func (h *UIHandler) updateMachineTokenForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	nodeIDs := r.Form["node_ids"]
	policyID := formPolicyID(r)
	canAttest := r.FormValue("can_attest_github_pushes") == "on"

	tok, err := h.db.GetMachineToken(id)
	if err != nil {
		slog.Error("get machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if tok == nil {
		http.NotFound(w, r)
		return
	}

	renderErr := func(msg string) {
		h.renderTokenForm(w, r, map[string]any{"IsNew": false, "Token": tok, "Error": msg},
			selectedSet(nodeIDs), derefString(policyID))
	}

	// Clearing all attachments is allowed — the token then vends nothing until
	// secrets and/or a policy are added again.
	if err := h.db.UpdateMachineTokenWithGitHubAttestation(
		id,
		policyID,
		nodeIDs,
		canAttest,
	); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			renderErr("The selected policy or secret no longer exists. Reload and try again.")
			return
		}
		slog.Error("update machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	details, _ := json.Marshal(map[string]any{
		"policy_id": derefString(policyID), "node_count": len(nodeIDs),
		"can_attest_github_pushes": canAttest,
	})
	if err := h.audit.CreateEntry("machine_token.update", "admin", uiActor(r), "machine_token", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/machine-tokens", http.StatusSeeOther)
}

func (h *UIHandler) regenerateMachineTokenForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tok, err := h.db.GetMachineToken(id)
	if err != nil {
		slog.Error("get machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if tok == nil {
		http.NotFound(w, r)
		return
	}
	token, err := h.db.RegenerateMachineToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("regenerate machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := h.audit.CreateEntry("machine_token.regenerate", "admin", uiActor(r), "machine_token", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}

	// Show the new token exactly once — the old value stopped working the
	// moment it was replaced.
	h.tmpl.Render(w, r, "machine_token_created.html", map[string]any{
		"Token":       token,
		"Name":        tok.Name,
		"Regenerated": true,
	})
}

func (h *UIHandler) deleteMachineTokenForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeleteMachineToken(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("delete machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := h.audit.CreateEntry("machine_token.delete", "admin", uiActor(r), "machine_token", id, "{}"); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/machine-tokens", http.StatusSeeOther)
}
