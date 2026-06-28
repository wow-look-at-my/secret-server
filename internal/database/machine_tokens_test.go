package database

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineTokenCreateAndLookup(t *testing.T) {
	db := testDB(t)
	p, err := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)

	token, rec, err := db.CreateMachineToken("reconcile", p.ID)
	require.Nil(t, err)
	require.NotNil(t, rec)
	assert.True(t, strings.HasPrefix(token, MachineTokenPrefix), "token should carry the sst_ prefix")
	assert.Equal(t, p.ID, rec.PolicyID)
	assert.True(t, strings.HasPrefix(rec.TokenPrefix, MachineTokenPrefix))

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, rec.ID, got.ID)
	assert.Equal(t, "reconcile", got.Name)
	assert.Equal(t, p.ID, got.PolicyID)
	assert.Equal(t, "p", got.PolicyName)
	assert.Nil(t, got.LastUsedAt, "a fresh token has never been used")
}

func TestMachineTokenLookupUnknownReturnsNil(t *testing.T) {
	db := testDB(t)
	got, err := db.LookupMachineToken(MachineTokenPrefix + "definitely-not-real")
	require.Nil(t, err)
	assert.Nil(t, got)

	// A value lacking the prefix is rejected without hitting the DB.
	got, err = db.LookupMachineToken("ghs_some_other_token")
	require.Nil(t, err)
	assert.Nil(t, got)
}

func TestMachineTokenTouchRecordsUsage(t *testing.T) {
	db := testDB(t)
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	token, rec, err := db.CreateMachineToken("x", p.ID)
	require.Nil(t, err)

	require.Nil(t, db.TouchMachineToken(rec.ID))

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.LastUsedAt, "last_used_at should be set after a touch")
}

func TestMachineTokenListDeleteCount(t *testing.T) {
	db := testDB(t)
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	token, rec, err := db.CreateMachineToken("reconcile", p.ID)
	require.Nil(t, err)

	list, err := db.ListMachineTokens()
	require.Nil(t, err)
	require.Equal(t, 1, len(list))
	assert.Equal(t, "reconcile", list[0].Name)
	assert.Equal(t, "p", list[0].PolicyName)
	assert.NotEqual(t, token, list[0].TokenPrefix, "the raw token is never stored")

	n, err := db.CountMachineTokens()
	require.Nil(t, err)
	assert.Equal(t, 1, n)

	require.Nil(t, db.DeleteMachineToken(rec.ID))
	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	assert.Nil(t, got, "a revoked token no longer resolves")
	assert.ErrorIs(t, db.DeleteMachineToken(rec.ID), ErrNotFound)
}

func TestMachineTokenCascadesOnPolicyDelete(t *testing.T) {
	db := testDB(t)
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	token, _, err := db.CreateMachineToken("x", p.ID)
	require.Nil(t, err)

	require.Nil(t, db.DeletePolicy(p.ID))

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	assert.Nil(t, got, "deleting the bound policy cascades to its machine tokens")
}

func TestMachineTokensAreUnique(t *testing.T) {
	db := testDB(t)
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	t1, _, err := db.CreateMachineToken("a", p.ID)
	require.Nil(t, err)
	t2, _, err := db.CreateMachineToken("b", p.ID)
	require.Nil(t, err)
	assert.NotEqual(t, t1, t2, "each minted token must be distinct")
}
