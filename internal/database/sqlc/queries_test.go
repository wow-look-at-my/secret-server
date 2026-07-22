package sqlcdb_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"

	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite DB with the composite schema.
// Mirrors internal/database/sqlc/schema/001_main.sql and 002_audit.sql.
func setupTestDB(t *testing.T) *sqlcdb.Queries {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(on)")
	require.Nil(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
		CREATE TABLE secret_nodes (
			id          TEXT PRIMARY KEY,
			kind        TEXT NOT NULL CHECK (kind IN ('secret', 'group')),
			parent_id   TEXT REFERENCES secret_nodes(id) ON DELETE CASCADE,
			name        TEXT NOT NULL,
			value       BLOB,
			created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			CHECK ((kind = 'secret' AND value IS NOT NULL)
				OR (kind = 'group'  AND value IS NULL))
		);
		CREATE UNIQUE INDEX idx_secret_nodes_secret_name ON secret_nodes(name) WHERE kind = 'secret';
		CREATE UNIQUE INDEX idx_secret_nodes_group_name  ON secret_nodes(parent_id, name) WHERE kind = 'group';

		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			mode TEXT NOT NULL DEFAULT 'pattern',
			github_environment TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL
		);
		CREATE TABLE policy_patterns (
			policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
			kind TEXT NOT NULL CHECK (kind IN ('repository','ref','actor')),
			pattern TEXT NOT NULL,
			PRIMARY KEY (policy_id, kind, pattern)
		);
		CREATE TABLE secret_node_policies (
			node_id TEXT NOT NULL REFERENCES secret_nodes(id) ON DELETE CASCADE,
			policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
			PRIMARY KEY (node_id, policy_id)
		);
		CREATE TABLE policy_precedence (
			node_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			depends_on_id TEXT NOT NULL,
			PRIMARY KEY (node_id, policy_id, depends_on_id),
			FOREIGN KEY (node_id, policy_id)     REFERENCES secret_node_policies(node_id, policy_id) ON DELETE CASCADE,
			FOREIGN KEY (node_id, depends_on_id) REFERENCES secret_node_policies(node_id, policy_id) ON DELETE CASCADE,
			CHECK (policy_id != depends_on_id)
		);
		CREATE TABLE audit_log (
			id TEXT PRIMARY KEY, timestamp DATETIME NOT NULL,
			action TEXT NOT NULL, actor_type TEXT NOT NULL, actor_id TEXT NOT NULL,
			resource_type TEXT NOT NULL, resource_id TEXT NOT NULL DEFAULT '',
			details TEXT NOT NULL DEFAULT '{}'
		);
	`)
	require.Nil(t, err)
	return sqlcdb.New(db)
}

func TestSecretNodeQueries(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create a group at the root.
	err := q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "g1", Kind: "group", Name: "app", CreatedAt: now, UpdatedAt: now,
	})
	require.Nil(t, err)

	// Create a secret inside the group.
	parent := sql.NullString{String: "g1", Valid: true}
	err = q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "s1", Kind: "secret", ParentID: parent, Name: "API_KEY",
		Value: []byte("enc"), CreatedAt: now, UpdatedAt: now,
	})
	require.Nil(t, err)

	// GetSecretNode.
	node, err := q.GetSecretNode(ctx, "s1")
	require.Nil(t, err)
	assert.Equal(t, "API_KEY", node.Name)
	assert.Equal(t, "secret", node.Kind)
	assert.Equal(t, "g1", node.ParentID.String)

	// ListRootNodes returns only the group.
	roots, err := q.ListRootNodes(ctx)
	require.Nil(t, err)
	require.Equal(t, 1, len(roots))
	assert.Equal(t, "g1", roots[0].ID)

	// ListChildNodes under the group returns the secret.
	kids, err := q.ListChildNodes(ctx, parent)
	require.Nil(t, err)
	require.Equal(t, 1, len(kids))
	assert.Equal(t, "s1", kids[0].ID)

	// CountNodesByKind.
	n, err := q.CountNodesByKind(ctx, "secret")
	require.Nil(t, err)
	assert.Equal(t, int64(1), n)

	// FindSecretByName.
	found, err := q.FindSecretByName(ctx, "API_KEY")
	require.Nil(t, err)
	assert.Equal(t, "s1", found.ID)

	// UpdateSecretNodeName.
	res, err := q.UpdateSecretNodeName(ctx, sqlcdb.UpdateSecretNodeNameParams{
		Name: "RENAMED", UpdatedAt: now, ID: "s1",
	})
	require.Nil(t, err)
	rows, _ := res.RowsAffected()
	assert.Equal(t, int64(1), rows)

	// UpdateSecretNodeValue.
	res, err = q.UpdateSecretNodeValue(ctx, sqlcdb.UpdateSecretNodeValueParams{
		Value: []byte("new-enc"), UpdatedAt: now, ID: "s1",
	})
	require.Nil(t, err)
	rows, _ = res.RowsAffected()
	assert.Equal(t, int64(1), rows)

	// DeleteSecretNode.
	res, err = q.DeleteSecretNode(ctx, "s1")
	require.Nil(t, err)
	rows, _ = res.RowsAffected()
	assert.Equal(t, int64(1), rows)
}

func TestPolicyQueries(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	err := q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{
		ID: "p1", Name: "Allow prod", Mode: "pattern", GithubEnvironment: "", CreatedAt: now,
	})
	require.Nil(t, err)

	p, err := q.GetPolicy(ctx, "p1")
	require.Nil(t, err)
	assert.Equal(t, "Allow prod", p.Name)

	policies, err := q.ListPolicies(ctx)
	require.Nil(t, err)
	assert.Equal(t, 1, len(policies))

	count, err := q.CountPolicies(ctx)
	require.Nil(t, err)
	assert.Equal(t, int64(1), count)

	res, err := q.UpdatePolicyName(ctx, sqlcdb.UpdatePolicyNameParams{
		Name: "Renamed", ID: "p1",
	})
	require.Nil(t, err)
	n, _ := res.RowsAffected()
	assert.Equal(t, int64(1), n)

	res, err = q.DeletePolicy(ctx, "p1")
	require.Nil(t, err)
	n, _ = res.RowsAffected()
	assert.Equal(t, int64(1), n)
}

func TestPolicyPatternQueries(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Need a policy row to reference.
	require.Nil(t, q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{ID: "p1", Name: "p", CreatedAt: now}))

	// Insert patterns of each kind.
	require.Nil(t, q.InsertPolicyPattern(ctx, sqlcdb.InsertPolicyPatternParams{PolicyID: "p1", Kind: "repository", Pattern: "myorg/*"}))
	require.Nil(t, q.InsertPolicyPattern(ctx, sqlcdb.InsertPolicyPatternParams{PolicyID: "p1", Kind: "ref", Pattern: "refs/heads/main"}))
	require.Nil(t, q.InsertPolicyPattern(ctx, sqlcdb.InsertPolicyPatternParams{PolicyID: "p1", Kind: "actor", Pattern: "*"}))

	patterns, err := q.ListPolicyPatterns(ctx, "p1")
	require.Nil(t, err)
	require.Equal(t, 3, len(patterns))

	// DeletePolicyPatternsOfKind.
	require.Nil(t, q.DeletePolicyPatternsOfKind(ctx, sqlcdb.DeletePolicyPatternsOfKindParams{
		PolicyID: "p1", Kind: "actor",
	}))
	patterns, err = q.ListPolicyPatterns(ctx, "p1")
	require.Nil(t, err)
	require.Equal(t, 2, len(patterns))

	// DeleteAllPolicyPatterns.
	require.Nil(t, q.DeleteAllPolicyPatterns(ctx, "p1"))
	patterns, err = q.ListPolicyPatterns(ctx, "p1")
	require.Nil(t, err)
	assert.Equal(t, 0, len(patterns))
}

func TestAttachDetachAndPrecedence(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Build a node and two policies.
	require.Nil(t, q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "n1", Kind: "group", Name: "g", CreatedAt: now, UpdatedAt: now,
	}))
	require.Nil(t, q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{ID: "pa", Name: "a", CreatedAt: now}))
	require.Nil(t, q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{ID: "pb", Name: "b", CreatedAt: now}))

	// Attach both.
	require.Nil(t, q.AttachNodePolicy(ctx, sqlcdb.AttachNodePolicyParams{NodeID: "n1", PolicyID: "pa"}))
	require.Nil(t, q.AttachNodePolicy(ctx, sqlcdb.AttachNodePolicyParams{NodeID: "n1", PolicyID: "pb"}))

	// ListNodePolicies.
	list, err := q.ListNodePolicies(ctx, "n1")
	require.Nil(t, err)
	assert.Equal(t, 2, len(list))

	cnt, err := q.CountAttachedPoliciesForNode(ctx, "n1")
	require.Nil(t, err)
	assert.Equal(t, int64(2), cnt)

	// Precedence edge a->b (a depends on b).
	require.Nil(t, q.AddPolicyPrecedence(ctx, sqlcdb.AddPolicyPrecedenceParams{
		NodeID: "n1", PolicyID: "pa", DependsOnID: "pb",
	}))
	edges, err := q.ListNodePolicyPrecedence(ctx, "n1")
	require.Nil(t, err)
	require.Equal(t, 1, len(edges))

	// RemovePolicyPrecedence.
	res, err := q.RemovePolicyPrecedence(ctx, sqlcdb.RemovePolicyPrecedenceParams{
		NodeID: "n1", PolicyID: "pa", DependsOnID: "pb",
	})
	require.Nil(t, err)
	n, _ := res.RowsAffected()
	assert.Equal(t, int64(1), n)

	// DetachNodePolicy.
	res, err = q.DetachNodePolicy(ctx, sqlcdb.DetachNodePolicyParams{NodeID: "n1", PolicyID: "pb"})
	require.Nil(t, err)
	n, _ = res.RowsAffected()
	assert.Equal(t, int64(1), n)

	// CountNodesReferencingPolicy.
	cnt, err = q.CountNodesReferencingPolicy(ctx, "pa")
	require.Nil(t, err)
	assert.Equal(t, int64(1), cnt)
}

func TestAuthorizedSecretsQuery(t *testing.T) {
	// Exercises the recursive-CTE query end to end. Build a small tree and
	// attach a policy; verify AuthorizedSecrets returns the inherited leaf.
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.Nil(t, q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "g1", Kind: "group", Name: "g", CreatedAt: now, UpdatedAt: now,
	}))
	parent := sql.NullString{String: "g1", Valid: true}
	require.Nil(t, q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "s1", Kind: "secret", ParentID: parent, Name: "LEAF",
		Value: []byte("v"), CreatedAt: now, UpdatedAt: now,
	}))
	require.Nil(t, q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{ID: "p1", Name: "p", CreatedAt: now}))
	require.Nil(t, q.AttachNodePolicy(ctx, sqlcdb.AttachNodePolicyParams{NodeID: "g1", PolicyID: "p1"}))

	rows, err := q.AuthorizedSecrets(ctx, []string{"p1"})
	require.Nil(t, err)
	require.Equal(t, 1, len(rows))
	assert.Equal(t, "LEAF", rows[0].Name)

	// Empty policy ID slice is the NULL path.
	rows, err = q.AuthorizedSecrets(ctx, nil)
	require.Nil(t, err)
	assert.Equal(t, 0, len(rows))
}

func TestListAllNodesQuery(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.Nil(t, q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "n1", Kind: "group", Name: "g", CreatedAt: now, UpdatedAt: now,
	}))
	require.Nil(t, q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "n2", Kind: "secret", Name: "SECRET", Value: []byte("v"),
		CreatedAt: now, UpdatedAt: now,
	}))

	all, err := q.ListAllNodes(ctx)
	require.Nil(t, err)
	assert.Equal(t, 2, len(all))
}

func TestListNodesReferencingPolicyQuery(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.Nil(t, q.CreateSecretNode(ctx, sqlcdb.CreateSecretNodeParams{
		ID: "n1", Kind: "group", Name: "g", CreatedAt: now, UpdatedAt: now,
	}))
	require.Nil(t, q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{ID: "p1", Name: "p", CreatedAt: now}))
	require.Nil(t, q.AttachNodePolicy(ctx, sqlcdb.AttachNodePolicyParams{NodeID: "n1", PolicyID: "p1"}))

	nodes, err := q.ListNodesReferencingPolicy(ctx, "p1")
	require.Nil(t, err)
	require.Equal(t, 1, len(nodes))
	assert.Equal(t, "n1", nodes[0].ID)
}

func TestFindSecretByNameNotFound(t *testing.T) {
	q := setupTestDB(t)
	_, err := q.FindSecretByName(context.Background(), "nothing")
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestAuditQueries(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	err := q.CreateAuditEntry(ctx, sqlcdb.CreateAuditEntryParams{
		ID: "a1", Timestamp: now, Action: "create_secret",
		ActorType: "user", ActorID: "admin@example.com",
		ResourceType: "secret", ResourceID: "s1", Details: `{"key":"API_KEY"}`,
	})
	require.Nil(t, err)

	entries, err := q.ListAuditEntries(ctx, sqlcdb.ListAuditEntriesParams{
		Limit: 10, Offset: 0,
	})
	require.Nil(t, err)
	assert.Equal(t, 1, len(entries))
	assert.Equal(t, "create_secret", entries[0].Action)

	count, err := q.CountAuditEntries(ctx)
	require.Nil(t, err)
	assert.Equal(t, int64(1), count)
}
