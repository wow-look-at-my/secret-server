package database

import (
	"strings"
	"testing"

	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestMachineTokenCreateAndLookup(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	token, rec, err := db.CreateMachineToken("reconcile", env.ID)
	require.Nil(t, err)
	require.NotNil(t, rec)
	assert.True(t, strings.HasPrefix(token, MachineTokenPrefix), "token should carry the sst_ prefix")
	assert.Equal(t, env.ID, rec.EnvironmentID)
	assert.True(t, strings.HasPrefix(rec.TokenPrefix, MachineTokenPrefix))
	assert.NotContains(t, token, " ")

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, rec.ID, got.ID)
	assert.Equal(t, "reconcile", got.Name)
	assert.Equal(t, "myapp", got.Project)
	assert.Equal(t, "prod", got.Environment)
	assert.Nil(t, got.LastUsedAt, "a fresh token has never been used")
}

func TestMachineTokenLookupUnknownReturnsNil(t *testing.T) {
	db := testDB(t)

	// Unknown token with the right prefix.
	got, err := db.LookupMachineToken(MachineTokenPrefix + "definitely-not-real")
	require.Nil(t, err)
	assert.Nil(t, got)

	// A value lacking the prefix is rejected without even hitting the DB.
	got, err = db.LookupMachineToken("ghs_some_oidc_or_other_token")
	require.Nil(t, err)
	assert.Nil(t, got)
}

func TestMachineTokenTouchRecordsUsage(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)
	token, rec, err := db.CreateMachineToken("reconcile", env.ID)
	require.Nil(t, err)

	require.Nil(t, db.TouchMachineToken(rec.ID))

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.LastUsedAt, "last_used_at should be set after a touch")
}

func TestMachineTokenListAndDelete(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)
	token, rec, err := db.CreateMachineToken("reconcile", env.ID)
	require.Nil(t, err)

	tokens, err := db.ListMachineTokens()
	require.Nil(t, err)
	require.Equal(t, 1, len(tokens))
	assert.Equal(t, "reconcile", tokens[0].Name)
	// The raw token is never stored, so the list can't leak it.
	assert.NotEqual(t, token, tokens[0].TokenPrefix)

	count, err := db.CountMachineTokens()
	require.Nil(t, err)
	assert.Equal(t, 1, count)

	require.Nil(t, db.DeleteMachineToken(rec.ID))

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	assert.Nil(t, got, "a revoked token no longer resolves")

	// Deleting again is a not-found.
	assert.ErrorIs(t, db.DeleteMachineToken(rec.ID), ErrNotFound)
}

func TestMachineTokensAreUnique(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	t1, _, err := db.CreateMachineToken("a", env.ID)
	require.Nil(t, err)
	t2, _, err := db.CreateMachineToken("b", env.ID)
	require.Nil(t, err)
	assert.NotEqual(t, t1, t2, "each minted token must be distinct")
}
