package handlers

import (
	"testing"

	"github.com/wow-look-at-my/secret-server/internal/database"
	"github.com/wow-look-at-my/testify/assert"
)

func TestToAuditViewsGitHubActions(t *testing.T) {
	entries := []database.AuditEntry{{
		Action:    "secret.access",
		ActorType: "github_actions",
		ActorID:   "myorg/repo",
		Details:   `{"repository":"myorg/repo","actor":"PazerOP","workflow":"deploy.yml","secrets_count":3,"ref":"refs/heads/main"}`,
	}}
	views := toAuditViews(entries)
	assert.Equal(t, 1, len(views))
	assert.Equal(t, "PazerOP", views[0].ActorDisplay)
	assert.Equal(t, "myorg/repo", views[0].ActorSubtext)
	assert.Equal(t, "workflow: deploy.yml, 3 secrets", views[0].DetailsSummary)
	// actor and repository should be removed from the map.
	_, hasActor := views[0].DetailsMap["actor"]
	_, hasRepo := views[0].DetailsMap["repository"]
	assert.False(t, hasActor)
	assert.False(t, hasRepo)
}

func TestToAuditViewsGitHubActionsNoActor(t *testing.T) {
	entries := []database.AuditEntry{{
		Action:    "secret.access",
		ActorType: "github_actions",
		ActorID:   "myorg/repo",
		Details:   `{"repository":"myorg/repo","workflow":"ci.yml","secrets_count":1}`,
	}}
	views := toAuditViews(entries)
	assert.Equal(t, "myorg/repo", views[0].ActorDisplay)
	assert.Equal(t, "myorg/repo", views[0].ActorSubtext)
}

func TestToAuditViewsAdmin(t *testing.T) {
	entries := []database.AuditEntry{{
		Action:    "secret.create",
		ActorType: "admin",
		ActorID:   "user@test.com",
		Details:   `{"key":"API_KEY"}`,
	}}
	views := toAuditViews(entries)
	assert.Equal(t, "admin: user@test.com", views[0].ActorDisplay)
	assert.Equal(t, "", views[0].ActorSubtext)
	assert.Equal(t, "key: API_KEY", views[0].DetailsSummary)
}

func TestToAuditViewsInvalidJSON(t *testing.T) {
	entries := []database.AuditEntry{{
		Action:    "secret.create",
		ActorType: "admin",
		ActorID:   "user@test.com",
		Details:   `not json`,
	}}
	views := toAuditViews(entries)
	assert.Nil(t, views[0].DetailsMap)
	assert.Equal(t, "", views[0].DetailsSummary)
}

func TestBuildDetailsSummaryDenied(t *testing.T) {
	m := map[string]any{"reason": "no_matching_policies"}
	assert.Equal(t, "denied: no_matching_policies", buildDetailsSummary("secret.access.denied", m))
}

func TestBuildDetailsSummaryPolicy(t *testing.T) {
	m := map[string]any{"name": "my-policy"}
	assert.Equal(t, "name: my-policy", buildDetailsSummary("policy.create", m))
}

func TestBuildDetailsSummaryEnvironment(t *testing.T) {
	m := map[string]any{"project": "myproject", "environment": "production"}
	assert.Equal(t, "myproject/production", buildDetailsSummary("environment.create", m))
}

func TestBuildDetailsSummaryNilMap(t *testing.T) {
	assert.Equal(t, "", buildDetailsSummary("secret.access", nil))
}

func TestBuildDetailsSummaryFallback(t *testing.T) {
	m := map[string]any{"unknown_key": "unknown_val"}
	s := buildDetailsSummary("other.action", m)
	assert.Contains(t, s, "unknown_key")
	assert.Contains(t, s, "unknown_val")
}
