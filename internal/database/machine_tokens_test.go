package database

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineTokenCreateAndLookup(t *testing.T) {
	db := testDB(t)
	s, err := db.CreateSecret(nil, "API_KEY", "shh")
	require.Nil(t, err)

	token, rec, err := db.CreateMachineToken("reconcile", []string{s.ID()})
	require.Nil(t, err)
	require.NotNil(t, rec)
	assert.True(t, strings.HasPrefix(token, MachineTokenPrefix), "token should carry the sst_ prefix")
	assert.True(t, strings.HasPrefix(rec.TokenPrefix, MachineTokenPrefix))

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, rec.ID, got.ID)
	assert.Equal(t, "reconcile", got.Name)
	assert.Nil(t, got.LastUsedAt, "a fresh token has never been used")

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), got.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"API_KEY": "shh"}, secrets, "the token vends its attached secret")
}

func TestMachineTokenGrantsGroupSubtree(t *testing.T) {
	db := testDB(t)
	g, err := db.CreateGroup(nil, "prod")
	require.Nil(t, err)
	gid := g.ID()
	_, err = db.CreateSecret(&gid, "A", "1")
	require.Nil(t, err)
	_, err = db.CreateSecret(&gid, "B", "2")
	require.Nil(t, err)

	_, rec, err := db.CreateMachineToken("t", []string{g.ID()})
	require.Nil(t, err)

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"A": "1", "B": "2"}, secrets, "attaching a group grants its whole subtree")
}

func TestMachineTokenWithNoNodesVendsNothing(t *testing.T) {
	db := testDB(t)
	_, rec, err := db.CreateMachineToken("empty", nil)
	require.Nil(t, err)
	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Empty(t, secrets)
}

func TestMachineTokenSetNodesReplaces(t *testing.T) {
	db := testDB(t)
	s1, _ := db.CreateSecret(nil, "S1", "v1")
	s2, _ := db.CreateSecret(nil, "S2", "v2")
	_, rec, err := db.CreateMachineToken("t", []string{s1.ID()})
	require.Nil(t, err)

	nodes, err := db.ListTokenNodes(rec.ID)
	require.Nil(t, err)
	require.Equal(t, 1, len(nodes))
	assert.Equal(t, "S1", nodes[0].Name)
	assert.Equal(t, "secret", nodes[0].Kind)

	require.Nil(t, db.SetTokenNodes(rec.ID, []string{s2.ID()}))
	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"S2": "v2"}, secrets, "set replaces the attachment set, it does not append")
}

func TestMachineTokenAttachUnknownNodeRollsBack(t *testing.T) {
	db := testDB(t)
	_, _, err := db.CreateMachineToken("t", []string{uuid.NewString()})
	assert.ErrorIs(t, err, ErrNotFound)
	n, _ := db.CountMachineTokens()
	assert.Equal(t, 0, n, "a failed attach rolls back the whole create")
}

func TestMachineTokenSetUnknownNodeKeepsPrior(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	_, rec, err := db.CreateMachineToken("t", []string{s.ID()})
	require.Nil(t, err)

	err = db.SetTokenNodes(rec.ID, []string{uuid.NewString()})
	assert.ErrorIs(t, err, ErrNotFound)

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"S": "v"}, secrets, "a failed update leaves the prior attachments intact")
}

func TestMachineTokenAttachmentCascadesOnSecretDelete(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	_, rec, err := db.CreateMachineToken("t", []string{s.ID()})
	require.Nil(t, err)

	require.Nil(t, db.DeleteNode(s.ID()))
	nodes, err := db.ListTokenNodes(rec.ID)
	require.Nil(t, err)
	assert.Empty(t, nodes, "deleting a secret removes it from tokens that referenced it")
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

func TestGetMachineToken(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	_, rec, err := db.CreateMachineToken("t", []string{s.ID()})
	require.Nil(t, err)

	got, err := db.GetMachineToken(rec.ID)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "t", got.Name)

	missing, err := db.GetMachineToken(uuid.NewString())
	require.Nil(t, err)
	assert.Nil(t, missing, "an unknown id yields (nil, nil)")
}

func TestMachineTokenTouchRecordsUsage(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	token, rec, err := db.CreateMachineToken("x", []string{s.ID()})
	require.Nil(t, err)

	require.Nil(t, db.TouchMachineToken(rec.ID))

	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.LastUsedAt, "last_used_at should be set after a touch")
}

func TestMachineTokenListDeleteCount(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	token, rec, err := db.CreateMachineToken("reconcile", []string{s.ID()})
	require.Nil(t, err)

	list, err := db.ListMachineTokens()
	require.Nil(t, err)
	require.Equal(t, 1, len(list))
	assert.Equal(t, "reconcile", list[0].Name)
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

func TestMachineTokensAreUnique(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	t1, _, err := db.CreateMachineToken("a", []string{s.ID()})
	require.Nil(t, err)
	t2, _, err := db.CreateMachineToken("b", []string{s.ID()})
	require.Nil(t, err)
	assert.NotEqual(t, t1, t2, "each minted token must be distinct")
}
