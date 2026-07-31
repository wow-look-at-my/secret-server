package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineTokenGitHubAttestationIsExplicitAndPersisted(t *testing.T) {
	db := testDB(t)
	token, rec, err := db.CreateMachineToken("agent-host", nil, nil)
	require.NoError(t, err)

	found, err := db.LookupMachineToken(token)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.False(t, found.CanAttestGitHubPushes)

	require.NoError(t, db.SetMachineTokenGitHubAttestation(
		context.Background(),
		rec.ID,
		true,
	))
	found, err = db.LookupMachineToken(token)
	require.NoError(t, err)
	assert.True(t, found.CanAttestGitHubPushes)

	require.NoError(t, db.UpdateMachineToken(rec.ID, nil, nil))
	found, err = db.LookupMachineToken(token)
	require.NoError(t, err)
	assert.True(t, found.CanAttestGitHubPushes, "ordinary grant updates preserve the separate capability")

	require.NoError(t, db.UpdateMachineTokenWithGitHubAttestation(
		rec.ID,
		nil,
		nil,
		false,
	))
	found, err = db.LookupMachineToken(token)
	require.NoError(t, err)
	assert.False(t, found.CanAttestGitHubPushes)

	err = db.UpdateMachineTokenWithGitHubAttestation(
		rec.ID,
		nil,
		[]string{"00000000-0000-0000-0000-000000000000"},
		true,
	)
	require.ErrorIs(t, err, ErrNotFound)
	found, err = db.LookupMachineToken(token)
	require.NoError(t, err)
	assert.False(t, found.CanAttestGitHubPushes, "failed updates roll back every authorization field")
}

func TestGitHubPushProvenanceExactLookupAndReplacement(t *testing.T) {
	db := testDB(t)
	_, rec, err := db.CreateMachineToken("agent-host", nil, nil)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	value := GitHubPushProvenance{
		Repository:     "Acme/Repo",
		Ref:            "refs/heads/main",
		SHA:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		GitHubUserID:   "6569500",
		GitHubLogin:    "PazerOP",
		MachineTokenID: rec.ID,
		AttestedAt:     now,
	}
	require.NoError(t, db.StoreGitHubPushProvenance(context.Background(), value))

	found, err := db.FindGitHubPushProvenance(
		context.Background(),
		"acme/repo",
		"refs/heads/main",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "6569500", found.GitHubUserID)
	assert.Equal(t, "PazerOP", found.GitHubLogin)

	value.GitHubUserID = "583231"
	value.GitHubLogin = "octocat"
	require.NoError(t, db.StoreGitHubPushProvenance(context.Background(), value))
	found, err = db.FindGitHubPushProvenance(
		context.Background(),
		"acme/repo",
		"refs/heads/main",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "583231", found.GitHubUserID)

	missing, err := db.FindGitHubPushProvenance(
		context.Background(),
		"acme/repo",
		"refs/heads/other",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	require.NoError(t, err)
	assert.Nil(t, missing)
}

func TestGitHubPushProvenanceRejectsIncompleteAndInvalidIdentity(t *testing.T) {
	db := testDB(t)
	err := db.StoreGitHubPushProvenance(
		context.Background(),
		GitHubPushProvenance{},
	)
	assert.ErrorContains(t, err, "incomplete")

	err = db.StoreGitHubPushProvenance(
		context.Background(),
		GitHubPushProvenance{
			Repository:     "acme/repo",
			Ref:            "refs/heads/main",
			SHA:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			GitHubUserID:   "not-a-number",
			GitHubLogin:    "octocat",
			MachineTokenID: "token-id",
		},
	)
	assert.ErrorContains(t, err, "invalid GitHub user ID")
}

func TestMachineTokenGitHubAttestationUnknownToken(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	err := db.SetMachineTokenGitHubAttestation(ctx, "missing", true)
	assert.ErrorIs(t, err, ErrNotFound)

	rec, err := db.GetMachineToken("missing")
	assert.NoError(t, err)
	assert.Nil(t, rec, "unknown token must return nil")
}
