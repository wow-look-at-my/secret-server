package database

import (
	"testing"

	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestPolicyCRUDGitHubEnvMode(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("app", "prod")
	require.Nil(t, err)

	p, err := db.CreatePolicy("ghenv", "github-environment", []string{"org/*"}, []string{"*"}, []string{"*"}, "production", env.ID)
	require.Nil(t, err)
	assert.Equal(t, "github-environment", p.Mode)
	assert.Equal(t, "production", p.GitHubEnvironment)

	got, err := db.GetPolicy(p.ID)
	require.Nil(t, err)
	assert.Equal(t, "github-environment", got.Mode)
	assert.Equal(t, "production", got.GitHubEnvironment)

	err = db.UpdatePolicy(p.ID, "updated", "pattern", []string{"org/*"}, []string{"*"}, []string{"*"}, "", env.ID)
	require.Nil(t, err)
	got, _ = db.GetPolicy(p.ID)
	assert.Equal(t, "pattern", got.Mode)
	assert.Equal(t, "", got.GitHubEnvironment)
}

func TestMatchingPoliciesGitHubEnvMode(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("app", "prod")
	require.Nil(t, err)

	db.CreatePolicy("ghenv", "github-environment", []string{"org/*"}, nil, nil, "production", env.ID)

	// Matching: repo matches, environment matches
	matched, err := db.MatchingPolicies("org/repo", "refs/heads/main", "anyone", "production")
	require.Nil(t, err)
	assert.Equal(t, 1, len(matched))

	// Non-matching: wrong environment
	matched, err = db.MatchingPolicies("org/repo", "refs/heads/main", "anyone", "staging")
	require.Nil(t, err)
	assert.Equal(t, 0, len(matched))

	// Non-matching: no environment claim
	matched, err = db.MatchingPolicies("org/repo", "refs/heads/main", "anyone", "")
	require.Nil(t, err)
	assert.Equal(t, 0, len(matched))

	// Non-matching: wrong repo
	matched, err = db.MatchingPolicies("other/repo", "refs/heads/main", "anyone", "production")
	require.Nil(t, err)
	assert.Equal(t, 0, len(matched))
}

func TestMatchingPoliciesMixedModes(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("app", "prod")
	require.Nil(t, err)

	db.CreatePolicy("pattern-policy", "", []string{"org/*"}, []string{"refs/heads/main"}, []string{"*"}, "", env.ID)
	db.CreatePolicy("ghenv-policy", "github-environment", []string{"org/*"}, nil, nil, "production", env.ID)

	// Both should match when all criteria align
	matched, err := db.MatchingPolicies("org/repo", "refs/heads/main", "someone", "production")
	require.Nil(t, err)
	assert.Equal(t, 2, len(matched))

	// Only pattern policy matches (no env claim)
	matched, err = db.MatchingPolicies("org/repo", "refs/heads/main", "someone", "")
	require.Nil(t, err)
	assert.Equal(t, 1, len(matched))
	assert.Equal(t, "pattern-policy", matched[0].Name)

	// Only ghenv policy matches (wrong ref for pattern)
	matched, err = db.MatchingPolicies("org/repo", "refs/heads/dev", "someone", "production")
	require.Nil(t, err)
	assert.Equal(t, 1, len(matched))
	assert.Equal(t, "ghenv-policy", matched[0].Name)
}
