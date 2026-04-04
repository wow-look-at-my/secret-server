package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wow-look-at-my/secret-server/internal/database"
)

// auditEntryView wraps an AuditEntry with display-ready fields for the template.
type auditEntryView struct {
	database.AuditEntry
	ActorDisplay   string
	ActorSubtext   string
	DetailsMap     map[string]any
	DetailsSummary string
}

func toAuditViews(entries []database.AuditEntry) []auditEntryView {
	views := make([]auditEntryView, len(entries))
	for i, e := range entries {
		v := auditEntryView{AuditEntry: e}

		var m map[string]any
		if err := json.Unmarshal([]byte(e.Details), &m); err == nil {
			v.DetailsMap = m
		}

		// Build actor display.
		if e.ActorType == "github_actions" && v.DetailsMap != nil {
			if actor, ok := v.DetailsMap["actor"].(string); ok && actor != "" {
				v.ActorDisplay = actor
			} else {
				v.ActorDisplay = e.ActorID
			}
			v.ActorSubtext = e.ActorID
			// Remove fields already shown in Actor column.
			delete(v.DetailsMap, "actor")
			delete(v.DetailsMap, "repository")
		} else {
			v.ActorDisplay = e.ActorType + ": " + e.ActorID
		}

		// Build summary line from details.
		v.DetailsSummary = buildDetailsSummary(e.Action, v.DetailsMap)

		views[i] = v
	}
	return views
}

func buildDetailsSummary(action string, m map[string]any) string {
	if m == nil {
		return ""
	}
	switch {
	case action == "secret.access":
		parts := []string{}
		if wf, ok := m["workflow"].(string); ok {
			parts = append(parts, "workflow: "+wf)
		}
		if n, ok := m["secrets_count"].(float64); ok {
			parts = append(parts, fmt.Sprintf("%d secrets", int(n)))
		}
		return strings.Join(parts, ", ")
	case action == "secret.access.denied":
		if reason, ok := m["reason"].(string); ok {
			return "denied: " + reason
		}
	case strings.HasPrefix(action, "secret."):
		if key, ok := m["key"].(string); ok {
			return "key: " + key
		}
	case strings.HasPrefix(action, "policy."):
		if name, ok := m["name"].(string); ok {
			return "name: " + name
		}
	case strings.HasPrefix(action, "environment."):
		proj, _ := m["project"].(string)
		env, _ := m["environment"].(string)
		if proj != "" && env != "" {
			return proj + "/" + env
		}
	}
	// Fallback: first key-value.
	for k, v := range m {
		return fmt.Sprintf("%s: %v", k, v)
	}
	return ""
}
