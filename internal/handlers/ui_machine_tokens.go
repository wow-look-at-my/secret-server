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
// A machine token attaches directly to secret-tree nodes and vends those
// secrets (a group grants its whole subtree) to non-Actions clients — no policy
// indirection. See internal/database/machine_tokens.go.

// nodeOption is one selectable secret-tree node in the token form's picker.
type nodeOption struct {
	ID       string
	Kind     string // "secret" or "group"
	Path     string // human path, e.g. "prod / api / GITHUB_APP_PRIVATE_KEY"
	Selected bool
}

// machineTokenListView pairs a token with the nodes it grants, for the list page.
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

func (h *UIHandler) newMachineToken(w http.ResponseWriter, r *http.Request) {
	opts, err := h.nodeOptions(nil)
	if err != nil {
		slog.Error("load nodes for machine token form failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
		"IsNew": true,
		"Nodes": opts,
	})
}

func (h *UIHandler) createMachineToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	nodeIDs := r.Form["node_ids"]

	renderErr := func(msg string) {
		opts, _ := h.nodeOptions(selectedSet(nodeIDs))
		h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
			"IsNew": true,
			"Error": msg,
			"Form":  r.Form,
			"Nodes": opts,
		})
	}

	if name == "" {
		renderErr("Name is required.")
		return
	}
	if len(nodeIDs) == 0 {
		renderErr("Select at least one secret or group for this token to grant.")
		return
	}

	token, rec, err := h.db.CreateMachineToken(name, nodeIDs)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			renderErr("One or more selected secrets no longer exist. Reload and try again.")
			return
		}
		slog.Error("create machine token failed", "error", err)
		renderErr("Failed to create machine token. Check server logs for details.")
		return
	}

	details, _ := json.Marshal(map[string]any{"name": name, "node_count": len(nodeIDs)})
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
	opts, err := h.nodeOptions(sel)
	if err != nil {
		slog.Error("load nodes for machine token form failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
		"IsNew": false,
		"Token": tok,
		"Nodes": opts,
	})
}

func (h *UIHandler) updateMachineTokenForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	nodeIDs := r.Form["node_ids"]

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
		opts, _ := h.nodeOptions(selectedSet(nodeIDs))
		h.tmpl.Render(w, r, "machine_token_form.html", map[string]any{
			"IsNew": false,
			"Token": tok,
			"Error": msg,
			"Nodes": opts,
		})
	}

	if len(nodeIDs) == 0 {
		renderErr("Select at least one secret or group.")
		return
	}
	if err := h.db.SetTokenNodes(id, nodeIDs); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			renderErr("One or more selected secrets no longer exist. Reload and try again.")
			return
		}
		slog.Error("update machine token failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	details, _ := json.Marshal(map[string]any{"node_count": len(nodeIDs)})
	if err := h.audit.CreateEntry("machine_token.update", "admin", uiActor(r), "machine_token", id, string(details)); err != nil {
		slog.Error("audit log failed", "error", err)
	}
	http.Redirect(w, r, AdminPrefix+"/machine-tokens", http.StatusSeeOther)
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
