package database

import (
	"database/sql"
	"testing"

	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func TestSecretChildrenReturnsNil(t *testing.T) {
	// A Secret is a leaf — Children() must always return nil so tree walks
	// can be uniform without type-switching.
	s := &Secret{id: "id", name: "n"}
	assert.Nil(t, s.Children())
}

func TestSecretGroupChildren(t *testing.T) {
	child := &Secret{id: "c"}
	g := &SecretGroup{id: "g", children: []ISecretNode{child}}
	got := g.Children()
	require.Equal(t, 1, len(got))
	assert.Equal(t, "c", got[0].ID())
}

func TestSortNodesGroupsBeforeSecrets(t *testing.T) {
	nodes := []ISecretNode{
		&Secret{id: "s1", name: "alpha"},
		&SecretGroup{id: "g1", name: "bravo"},
		&Secret{id: "s2", name: "charlie"},
		&SecretGroup{id: "g2", name: "alpha"},
	}
	sortNodes(nodes)
	// Groups come before secrets, each block sorted by name.
	assert.Equal(t, "g2", nodes[0].ID()) // group "alpha"
	assert.Equal(t, "g1", nodes[1].ID()) // group "bravo"
	assert.Equal(t, "s1", nodes[2].ID()) // secret "alpha"
	assert.Equal(t, "s2", nodes[3].ID()) // secret "charlie"
}

func TestNullStringFromPtr(t *testing.T) {
	n := nullStringFromPtr(nil)
	assert.False(t, n.Valid)

	s := "hello"
	n = nullStringFromPtr(&s)
	assert.True(t, n.Valid)
	assert.Equal(t, "hello", n.String)
}

func TestPtrFromNullString(t *testing.T) {
	assert.Nil(t, ptrFromNullString(sql.NullString{Valid: false}))
	p := ptrFromNullString(sql.NullString{String: "hello", Valid: true})
	require.NotNil(t, p)
	assert.Equal(t, "hello", *p)
}

// TestRemovePrecedenceFunction exercises the RemovePrecedence wrapper
// directly (the admin test covers the handler path, but not the DB wrapper).
func TestRemovePrecedenceFunction(t *testing.T) {
	db := testDB(t)
	g, _ := db.CreateGroup(nil, "g")
	a, _ := db.CreatePolicy("a", []string{"*"}, []string{"*"}, []string{"*"})
	b, _ := db.CreatePolicy("b", []string{"*"}, []string{"*"}, []string{"*"})
	db.AttachPolicy(g.ID(), a.ID)
	db.AttachPolicy(g.ID(), b.ID)
	require.Nil(t, db.AddPrecedence(g.ID(), a.ID, b.ID))

	require.Nil(t, db.RemovePrecedence(g.ID(), a.ID, b.ID))

	// Removing again should return ErrNotFound.
	err := db.RemovePrecedence(g.ID(), a.ID, b.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestMergeSortedPolicies(t *testing.T) {
	// Direct unit test for the sort helper. Both inputs must already be
	// sorted by name; merged output preserves order.
	a := []sqlcdb.AccessPolicy{{ID: "1", Name: "a"}, {ID: "3", Name: "c"}}
	b := []sqlcdb.AccessPolicy{{ID: "2", Name: "b"}, {ID: "4", Name: "d"}}
	got := mergeSortedPolicies(a, b)
	require.Equal(t, 4, len(got))
	assert.Equal(t, "a", got[0].Name)
	assert.Equal(t, "b", got[1].Name)
	assert.Equal(t, "c", got[2].Name)
	assert.Equal(t, "d", got[3].Name)

	// One side empty.
	got = mergeSortedPolicies(a, nil)
	assert.Equal(t, 2, len(got))
	got = mergeSortedPolicies(nil, b)
	assert.Equal(t, 2, len(got))
}

func TestReachableFunction(t *testing.T) {
	// Direct tests for reachable (simpler than setting up a full DB).
	edges := []sqlcdb.PolicyPrecedence{
		{PolicyID: "a", DependsOnID: "b"}, // b -> a
		{PolicyID: "b", DependsOnID: "c"}, // c -> b
	}
	// From c, can we reach a? c -> b -> a, yes.
	assert.True(t, reachable(edges, "c", "a"))
	// From a, can we reach c? No (no outgoing edges from a).
	assert.False(t, reachable(edges, "a", "c"))
	// Same node.
	assert.True(t, reachable(edges, "a", "a"))
}

func TestTopoSortWithCycle(t *testing.T) {
	// Build a degenerate graph the DB shouldn't normally produce but
	// topoSortPolicies must still handle: a->b, b->a (cycle).
	policies := []sqlcdb.AccessPolicy{
		{ID: "a", Name: "a"},
		{ID: "b", Name: "b"},
	}
	edges := []sqlcdb.PolicyPrecedence{
		{PolicyID: "a", DependsOnID: "b"},
		{PolicyID: "b", DependsOnID: "a"},
	}
	_, err := topoSortPolicies(policies, edges)
	require.NotNil(t, err)
}

func TestTopoSortEmpty(t *testing.T) {
	out, err := topoSortPolicies(nil, nil)
	require.Nil(t, err)
	assert.Nil(t, out)
}
