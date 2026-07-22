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

	token, rec, err := db.CreateMachineToken("reconcile", nil, []string{s.ID()})
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

	_, rec, err := db.CreateMachineToken("t", nil, []string{g.ID()})
	require.Nil(t, err)

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"A": "1", "B": "2"}, secrets, "attaching a group grants its whole subtree")
}

func TestMachineTokenWithNoNodesVendsNothing(t *testing.T) {
	db := testDB(t)
	_, rec, err := db.CreateMachineToken("empty", nil, nil)
	require.Nil(t, err)
	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Empty(t, secrets)
}

func TestMachineTokenSetNodesReplaces(t *testing.T) {
	db := testDB(t)
	s1, _ := db.CreateSecret(nil, "S1", "v1")
	s2, _ := db.CreateSecret(nil, "S2", "v2")
	_, rec, err := db.CreateMachineToken("t", nil, []string{s1.ID()})
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
	_, _, err := db.CreateMachineToken("t", nil, []string{uuid.NewString()})
	assert.ErrorIs(t, err, ErrNotFound)
	n, _ := db.CountMachineTokens()
	assert.Equal(t, 0, n, "a failed attach rolls back the whole create")
}

func TestMachineTokenSetUnknownNodeKeepsPrior(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	_, rec, err := db.CreateMachineToken("t", nil, []string{s.ID()})
	require.Nil(t, err)

	err = db.SetTokenNodes(rec.ID, []string{uuid.NewString()})
	assert.ErrorIs(t, err, ErrNotFound)

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"S": "v"}, secrets, "a failed update leaves the prior attachments intact")
}

func TestMachineTokenSeedNodeIDs(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	// Direct-attach seed: a secret attached straight to a token.
	direct, _ := db.CreateSecret(nil, "DIRECT", "v")
	_, _, err := db.CreateMachineToken("direct", nil, []string{direct.ID()})
	require.Nil(t, err)

	// Policy-bound seed: a group with a policy attached, and a token bound to
	// that policy. The seed is the group node (where the policy is attached),
	// not the subtree leaves — the caller expands inheritance downward.
	g, _ := db.CreateGroup(nil, "viapolicy")
	gid := g.ID()
	_, _ = db.CreateSecret(&gid, "CHILD", "v")
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	require.Nil(t, db.AttachPolicy(gid, p.ID))
	_, _, err = db.CreateMachineToken("bound", &p.ID, nil)
	require.Nil(t, err)

	// A secret reachable by neither a token nor a token-bound policy.
	lonely, _ := db.CreateSecret(nil, "LONELY", "v")

	seed, err := db.MachineTokenSeedNodeIDs(ctx)
	require.Nil(t, err)
	assert.True(t, seed[direct.ID()], "directly-attached node is in the seed")
	assert.True(t, seed[gid], "policy-bound group node is in the seed")
	assert.False(t, seed[lonely.ID()], "an unattached node is not in the seed")
}

func TestMachineTokenSeedNodeIDsEmpty(t *testing.T) {
	db := testDB(t)
	// A policy attached to a node but with NO token bound to it must not seed.
	g, _ := db.CreateGroup(nil, "g")
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	require.Nil(t, db.AttachPolicy(g.ID(), p.ID))

	seed, err := db.MachineTokenSeedNodeIDs(context.Background())
	require.Nil(t, err)
	assert.Empty(t, seed, "a policy with no machine token bound contributes no seed")
}

func TestMachineTokenAttachmentCascadesOnSecretDelete(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	_, rec, err := db.CreateMachineToken("t", nil, []string{s.ID()})
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
	_, rec, err := db.CreateMachineToken("t", nil, []string{s.ID()})
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
	token, rec, err := db.CreateMachineToken("x", nil, []string{s.ID()})
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
	token, rec, err := db.CreateMachineToken("reconcile", nil, []string{s.ID()})
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
	t1, _, err := db.CreateMachineToken("a", nil, []string{s.ID()})
	require.Nil(t, err)
	t2, _, err := db.CreateMachineToken("b", nil, []string{s.ID()})
	require.Nil(t, err)
	assert.NotEqual(t, t1, t2, "each minted token must be distinct")
}

func TestMachineTokenWithPolicyOnly(t *testing.T) {
	db := testDB(t)
	p, err := db.CreatePolicy("pol", nil, nil, nil)
	require.Nil(t, err)
	sec, _ := db.CreateSecret(nil, "POLSECRET", "pv")
	require.Nil(t, db.AttachPolicy(sec.ID(), p.ID))

	_, rec, err := db.CreateMachineToken("t", &p.ID, nil)
	require.Nil(t, err)
	require.NotNil(t, rec.PolicyID)
	assert.Equal(t, p.ID, *rec.PolicyID)

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"POLSECRET": "pv"}, secrets, "a policy-only token vends the policy's secrets")
}

func TestMachineTokenUnionPolicyAndDirect(t *testing.T) {
	db := testDB(t)
	p, _ := db.CreatePolicy("pol", nil, nil, nil)
	polSec, _ := db.CreateSecret(nil, "VIA_POLICY", "pv")
	require.Nil(t, db.AttachPolicy(polSec.ID(), p.ID))
	direct, _ := db.CreateSecret(nil, "DIRECT", "dv")

	_, rec, err := db.CreateMachineToken("t", &p.ID, []string{direct.ID()})
	require.Nil(t, err)

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"VIA_POLICY": "pv", "DIRECT": "dv"}, secrets,
		"a token vends the union of its policy's secrets and its direct attachments")
}

func TestMachineTokenCreateUnknownPolicyRollsBack(t *testing.T) {
	db := testDB(t)
	bogus := uuid.NewString()
	_, _, err := db.CreateMachineToken("t", &bogus, nil)
	assert.ErrorIs(t, err, ErrNotFound)
	n, _ := db.CountMachineTokens()
	assert.Equal(t, 0, n, "an unknown policy fails the whole create")
}

func TestUpdateMachineTokenPolicyAndNodes(t *testing.T) {
	db := testDB(t)
	p, _ := db.CreatePolicy("pol", nil, nil, nil)
	polSec, _ := db.CreateSecret(nil, "POL", "pv")
	require.Nil(t, db.AttachPolicy(polSec.ID(), p.ID))
	a, _ := db.CreateSecret(nil, "A", "1")
	b, _ := db.CreateSecret(nil, "B", "2")

	_, rec, err := db.CreateMachineToken("t", nil, []string{a.ID()})
	require.Nil(t, err)

	// Bind the policy and switch the direct attachment to B.
	require.Nil(t, db.UpdateMachineToken(rec.ID, &p.ID, []string{b.ID()}))
	got, _ := db.GetMachineToken(rec.ID)
	require.NotNil(t, got.PolicyID)
	assert.Equal(t, p.ID, *got.PolicyID)
	secrets, err := db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"POL": "pv", "B": "2"}, secrets)

	// Unbind the policy (nil), keep B.
	require.Nil(t, db.UpdateMachineToken(rec.ID, nil, []string{b.ID()}))
	got, _ = db.GetMachineToken(rec.ID)
	assert.Nil(t, got.PolicyID, "policy unbound")
	secrets, _ = db.AuthorizedSecretsForToken(context.Background(), rec.ID)
	assert.Equal(t, map[string]string{"B": "2"}, secrets)
}

func TestRegenerateMachineToken(t *testing.T) {
	db := testDB(t)
	p, err := db.CreatePolicy("pol", nil, nil, nil)
	require.Nil(t, err)
	s, _ := db.CreateSecret(nil, "S", "v")
	oldToken, rec, err := db.CreateMachineToken("rotate-me", &p.ID, []string{s.ID()})
	require.Nil(t, err)

	newToken, err := db.RegenerateMachineToken(context.Background(), rec.ID)
	require.Nil(t, err)
	assert.True(t, strings.HasPrefix(newToken, MachineTokenPrefix), "regenerated token carries the sst_ prefix")
	assert.NotEqual(t, oldToken, newToken, "regeneration mints a distinct value")

	// The new token resolves to the same record; the old one is dead.
	got, err := db.LookupMachineToken(newToken)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, rec.ID, got.ID)
	assert.True(t, strings.HasPrefix(newToken, got.TokenPrefix), "the display prefix tracks the new value")
	old, err := db.LookupMachineToken(oldToken)
	require.Nil(t, err)
	assert.Nil(t, old, "the old token no longer resolves")

	// Name, bound policy, and node attachments are untouched.
	assert.Equal(t, "rotate-me", got.Name)
	require.NotNil(t, got.PolicyID)
	assert.Equal(t, p.ID, *got.PolicyID)
	nodes, err := db.ListTokenNodes(rec.ID)
	require.Nil(t, err)
	require.Equal(t, 1, len(nodes))
	assert.Equal(t, "S", nodes[0].Name)
}

func TestRegenerateMachineTokenUnknownID(t *testing.T) {
	db := testDB(t)
	_, err := db.RegenerateMachineToken(context.Background(), uuid.NewString())
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestRegenerateMachineTokenDBError(t *testing.T) {
	db := testDB(t)
	s, _ := db.CreateSecret(nil, "S", "v")
	_, rec, err := db.CreateMachineToken("t", nil, []string{s.ID()})
	require.Nil(t, err)

	db.Close()
	_, err = db.RegenerateMachineToken(context.Background(), rec.ID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound, "a query failure is not reported as a missing token")
}

func TestUpdateMachineTokenUnknownPolicyKeepsPrior(t *testing.T) {
	db := testDB(t)
	a, _ := db.CreateSecret(nil, "A", "1")
	_, rec, err := db.CreateMachineToken("t", nil, []string{a.ID()})
	require.Nil(t, err)

	bogus := uuid.NewString()
	err = db.UpdateMachineToken(rec.ID, &bogus, []string{a.ID()})
	assert.ErrorIs(t, err, ErrNotFound)

	got, _ := db.GetMachineToken(rec.ID)
	assert.Nil(t, got.PolicyID, "a failed update leaves the token unbound")
}
