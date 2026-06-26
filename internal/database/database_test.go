package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)

	f, err := os.CreateTemp(t.TempDir(), "test-*.db")
	require.Nil(t, err)
	f.Close()

	db, err := New(f.Name(), enc)
	require.Nil(t, err)

	t.Cleanup(func() { db.Close() })
	return db
}

// strPtr is a helper for building *string values in table-driven tests.
func strPtr(s string) *string { return &s }

func TestFreshDatabaseHasCompositeSchema(t *testing.T) {
	db := testDB(t)
	// Verify secret_nodes table exists and environments does not.
	var name string
	err := db.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='secret_nodes'`).Scan(&name)
	require.Nil(t, err)
	assert.Equal(t, "secret_nodes", name)

	err = db.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='environments'`).Scan(&name)
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestCreateGroupAndSecret(t *testing.T) {
	db := testDB(t)

	g, err := db.CreateGroup(nil, "myapp")
	require.Nil(t, err)
	require.NotEqual(t, "", g.ID())
	assert.Equal(t, "myapp", g.Name())
	assert.Nil(t, g.ParentID())

	gID := g.ID()
	s, err := db.CreateSecret(&gID, "DATABASE_URL", "postgres://...")
	require.Nil(t, err)
	assert.Equal(t, "DATABASE_URL", s.Name())
	require.NotNil(t, s.ParentID())
	assert.Equal(t, gID, *s.ParentID())
	assert.Equal(t, "postgres://...", s.Value)
}

func TestCreateGroupEmptyName(t *testing.T) {
	db := testDB(t)
	_, err := db.CreateGroup(nil, "")
	require.NotNil(t, err)
}

func TestCreateSecretEmptyName(t *testing.T) {
	db := testDB(t)
	_, err := db.CreateSecret(nil, "", "val")
	require.NotNil(t, err)
}

func TestGlobalUniqueSecretName(t *testing.T) {
	db := testDB(t)

	// Create two disjoint groups.
	g1, err := db.CreateGroup(nil, "a")
	require.Nil(t, err)
	g2, err := db.CreateGroup(nil, "b")
	require.Nil(t, err)

	g1ID := g1.ID()
	g2ID := g2.ID()

	_, err = db.CreateSecret(&g1ID, "DATABASE_URL", "one")
	require.Nil(t, err)

	// Creating a second secret with the same name under a DIFFERENT parent
	// must fail — secret names are globally unique.
	_, err = db.CreateSecret(&g2ID, "DATABASE_URL", "two")
	require.NotNil(t, err)
}

func TestGroupNamesPerParentUnique(t *testing.T) {
	db := testDB(t)

	// Two sibling groups under the same parent cannot share a name.
	parent, err := db.CreateGroup(nil, "parent")
	require.Nil(t, err)
	parentID := parent.ID()

	_, err = db.CreateGroup(&parentID, "prod")
	require.Nil(t, err)
	_, err = db.CreateGroup(&parentID, "prod")
	require.NotNil(t, err)

	// But a "prod" group under a DIFFERENT parent is fine.
	other, err := db.CreateGroup(nil, "other")
	require.Nil(t, err)
	otherID := other.ID()
	_, err = db.CreateGroup(&otherID, "prod")
	require.Nil(t, err)
}

func TestGetSecretAndGetNode(t *testing.T) {
	db := testDB(t)

	s, err := db.CreateSecret(nil, "API_KEY", "xyz")
	require.Nil(t, err)

	// GetSecret returns the decrypted value.
	got, err := db.GetSecret(s.ID())
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "xyz", got.Value)

	// GetNode on a secret ID returns a *Secret.
	n, err := db.GetNode(s.ID())
	require.Nil(t, err)
	require.NotNil(t, n)
	_, ok := n.(*Secret)
	assert.True(t, ok)

	// GetNode on a nonexistent ID returns nil, nil.
	n, err = db.GetNode("00000000-0000-0000-0000-000000000000")
	require.Nil(t, err)
	assert.Nil(t, n)
}

func TestLoadSubtree(t *testing.T) {
	db := testDB(t)

	root, _ := db.CreateGroup(nil, "root")
	rootID := root.ID()
	sub, _ := db.CreateGroup(&rootID, "sub")
	subID := sub.ID()
	db.CreateSecret(&subID, "leaf1", "v1")
	db.CreateSecret(&subID, "leaf2", "v2")

	// LoadSubtree(nil) returns all roots with children populated.
	roots, err := db.LoadSubtree(nil)
	require.Nil(t, err)
	require.Equal(t, 1, len(roots))
	g, ok := roots[0].(*SecretGroup)
	require.True(t, ok)
	assert.Equal(t, "root", g.Name())
	require.Equal(t, 1, len(g.Children()))
	subGroup, ok := g.Children()[0].(*SecretGroup)
	require.True(t, ok)
	assert.Equal(t, 2, len(subGroup.Children()))
	// All leaves are decrypted.
	for _, c := range subGroup.Children() {
		leaf, ok := c.(*Secret)
		require.True(t, ok)
		assert.Contains(t, []string{"v1", "v2"}, leaf.Value)
	}

	// LoadSubtree(&rootID) returns just that subtree.
	just, err := db.LoadSubtree(&rootID)
	require.Nil(t, err)
	require.Equal(t, 1, len(just))
}

func TestRenameMoveDeleteNode(t *testing.T) {
	db := testDB(t)

	g, _ := db.CreateGroup(nil, "g1")
	gID := g.ID()
	s, _ := db.CreateSecret(&gID, "NAME1", "v")

	// Rename.
	err := db.RenameNode(s.ID(), "NAME2")
	require.Nil(t, err)
	got, _ := db.GetSecret(s.ID())
	assert.Equal(t, "NAME2", got.Name())

	// Move to root.
	err = db.MoveNode(s.ID(), nil)
	require.Nil(t, err)
	got, _ = db.GetSecret(s.ID())
	assert.Nil(t, got.ParentID())

	// Update value.
	err = db.UpdateSecretValue(s.ID(), "new-val")
	require.Nil(t, err)
	got, _ = db.GetSecret(s.ID())
	assert.Equal(t, "new-val", got.Value)

	// Delete.
	err = db.DeleteNode(s.ID())
	require.Nil(t, err)
	got, _ = db.GetSecret(s.ID())
	assert.Nil(t, got)
}

func TestDeleteGroupCascadesChildren(t *testing.T) {
	db := testDB(t)

	g, _ := db.CreateGroup(nil, "g")
	gID := g.ID()
	s, _ := db.CreateSecret(&gID, "LEAF", "v")

	err := db.DeleteNode(gID)
	require.Nil(t, err)

	// Child should have been cascaded away.
	got, err := db.GetSecret(s.ID())
	require.Nil(t, err)
	assert.Nil(t, got)
}

func TestRenameNotFound(t *testing.T) {
	db := testDB(t)
	err := db.RenameNode("00000000-0000-0000-0000-000000000000", "new-name")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestUpdateSecretValueOnlyUpdatesSecrets(t *testing.T) {
	db := testDB(t)
	g, _ := db.CreateGroup(nil, "group")
	// UpdateSecretValue against a group ID should return ErrNotFound (the
	// underlying WHERE clause excludes non-secret rows).
	err := db.UpdateSecretValue(g.ID(), "nope")
	require.ErrorIs(t, err, ErrNotFound)
}

// --- Policies ---

func TestPolicyCRUD(t *testing.T) {
	db := testDB(t)

	p, err := db.CreatePolicy("Allow prod", []string{"myorg/*"}, []string{"refs/heads/main"}, []string{"*"})
	require.Nil(t, err)
	require.NotEqual(t, "", p.ID)

	got, err := db.GetPolicy(p.ID)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "Allow prod", got.Name)
	assert.Equal(t, []string{"myorg/*"}, got.RepositoryPatterns)
	assert.Equal(t, []string{"refs/heads/main"}, got.RefPatterns)
	assert.Equal(t, []string{"*"}, got.ActorPatterns)

	policies, err := db.ListPolicies()
	require.Nil(t, err)
	require.Equal(t, 1, len(policies))

	err = db.UpdatePolicy(p.ID, "Updated", []string{"other/*"}, []string{"*"}, []string{"*"})
	require.Nil(t, err)

	got, _ = db.GetPolicy(p.ID)
	assert.Equal(t, "Updated", got.Name)
	assert.Equal(t, []string{"other/*"}, got.RepositoryPatterns)

	err = db.DeletePolicy(p.ID)
	require.Nil(t, err)
	got, _ = db.GetPolicy(p.ID)
	assert.Nil(t, got)
}

func TestCreatePolicyValidation(t *testing.T) {
	db := testDB(t)

	// Empty name is rejected.
	_, err := db.CreatePolicy("", []string{"*"}, []string{"*"}, []string{"*"})
	require.NotNil(t, err)

	// Invalid glob pattern is rejected.
	_, err = db.CreatePolicy("bad", []string{"org/["}, []string{"*"}, []string{"*"})
	require.NotNil(t, err)
}

func TestMatchingPolicyIDs(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	p1, _ := db.CreatePolicy("p1", []string{"myorg/*"}, []string{"refs/heads/main"}, []string{"*"})
	db.CreatePolicy("p2", []string{"myorg/specific"}, []string{"*"}, []string{"*"})
	db.CreatePolicy("p3", []string{"other/*"}, []string{"*"}, []string{"*"})

	// Only p1 matches this claim tuple.
	ids, err := db.MatchingPolicyIDs(ctx, "myorg/repo", "refs/heads/main", "someone")
	require.Nil(t, err)
	assert.Equal(t, []string{p1.ID}, ids)

	// myorg/specific + main matches BOTH p1 and p2.
	ids, err = db.MatchingPolicyIDs(ctx, "myorg/specific", "refs/heads/main", "someone")
	require.Nil(t, err)
	assert.Equal(t, 2, len(ids))

	// No match for unknown repo.
	ids, err = db.MatchingPolicyIDs(ctx, "unknown/repo", "refs/heads/main", "someone")
	require.Nil(t, err)
	assert.Equal(t, 0, len(ids))
}

func TestMatchingPolicyIDsEmptyKindMatchesNothing(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	// Zero ref and zero actor patterns — under the new semantics this
	// policy matches nothing because the inner JOINs yield no rows.
	_, err := db.CreatePolicy("only-repo", []string{"myorg/*"}, nil, nil)
	require.Nil(t, err)

	ids, err := db.MatchingPolicyIDs(ctx, "myorg/repo", "refs/heads/main", "rando")
	require.Nil(t, err)
	assert.Equal(t, 0, len(ids))
}

func TestMatchingPolicyIDsActorFilter(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	p, _ := db.CreatePolicy("deployers-only", []string{"myorg/*"}, []string{"*"}, []string{"deploy-*"})

	ids, err := db.MatchingPolicyIDs(ctx, "myorg/repo", "refs/heads/main", "deploy-bot")
	require.Nil(t, err)
	assert.Equal(t, []string{p.ID}, ids)

	ids, err = db.MatchingPolicyIDs(ctx, "myorg/repo", "refs/heads/main", "random-user")
	require.Nil(t, err)
	assert.Equal(t, 0, len(ids))
}

// --- Attach/detach, authorized secrets, precedence ---

func TestAttachDetachAndAuthorizedSecrets(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	// Build a tree: group -> secret
	g, _ := db.CreateGroup(nil, "app")
	gID := g.ID()
	s, _ := db.CreateSecret(&gID, "API_KEY", "xyz")
	p, _ := db.CreatePolicy("pol", []string{"myorg/*"}, []string{"*"}, []string{"*"})

	// No attachment yet: query returns empty.
	secrets, err := db.AuthorizedSecrets(ctx, []string{p.ID})
	require.Nil(t, err)
	assert.Equal(t, 0, len(secrets))

	// Attach to the GROUP — inheritance flows down to the leaf.
	err = db.AttachPolicy(gID, p.ID)
	require.Nil(t, err)

	secrets, err = db.AuthorizedSecrets(ctx, []string{p.ID})
	require.Nil(t, err)
	require.Equal(t, 1, len(secrets))
	assert.Equal(t, "xyz", secrets["API_KEY"])

	// Detach — no more access.
	err = db.DetachPolicy(gID, p.ID)
	require.Nil(t, err)
	secrets, err = db.AuthorizedSecrets(ctx, []string{p.ID})
	require.Nil(t, err)
	assert.Equal(t, 0, len(secrets))

	// Attach directly to the LEAF instead.
	err = db.AttachPolicy(s.ID(), p.ID)
	require.Nil(t, err)
	secrets, err = db.AuthorizedSecrets(ctx, []string{p.ID})
	require.Nil(t, err)
	require.Equal(t, 1, len(secrets))
}

func TestAuthorizedSecretsEmptyPolicyList(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	secrets, err := db.AuthorizedSecrets(ctx, nil)
	require.Nil(t, err)
	assert.Equal(t, 0, len(secrets))
}

func TestListNodePoliciesOrderedByName(t *testing.T) {
	db := testDB(t)
	g, _ := db.CreateGroup(nil, "g")
	// Create three policies in non-alphabetical order.
	p1, _ := db.CreatePolicy("charlie", []string{"*"}, []string{"*"}, []string{"*"})
	p2, _ := db.CreatePolicy("alpha", []string{"*"}, []string{"*"}, []string{"*"})
	p3, _ := db.CreatePolicy("bravo", []string{"*"}, []string{"*"}, []string{"*"})

	db.AttachPolicy(g.ID(), p1.ID)
	db.AttachPolicy(g.ID(), p2.ID)
	db.AttachPolicy(g.ID(), p3.ID)

	// With no precedence edges the topo sort falls back to alphabetical.
	got, err := db.ListNodePolicies(g.ID())
	require.Nil(t, err)
	require.Equal(t, 3, len(got))
	assert.Equal(t, "alpha", got[0].Name)
	assert.Equal(t, "bravo", got[1].Name)
	assert.Equal(t, "charlie", got[2].Name)
}

func TestPrecedenceOrdering(t *testing.T) {
	db := testDB(t)
	g, _ := db.CreateGroup(nil, "g")

	// b, a, c — alphabetical would be a, b, c. Attach an edge saying b must
	// run before a and before c, forcing b to appear first.
	a, _ := db.CreatePolicy("a", []string{"*"}, []string{"*"}, []string{"*"})
	b, _ := db.CreatePolicy("b", []string{"*"}, []string{"*"}, []string{"*"})
	c, _ := db.CreatePolicy("c", []string{"*"}, []string{"*"}, []string{"*"})

	db.AttachPolicy(g.ID(), a.ID)
	db.AttachPolicy(g.ID(), b.ID)
	db.AttachPolicy(g.ID(), c.ID)

	// a depends on b (b first), c depends on b (b first).
	require.Nil(t, db.AddPrecedence(g.ID(), a.ID, b.ID))
	require.Nil(t, db.AddPrecedence(g.ID(), c.ID, b.ID))

	got, err := db.ListNodePolicies(g.ID())
	require.Nil(t, err)
	require.Equal(t, 3, len(got))
	assert.Equal(t, "b", got[0].Name)
	// Among remaining a/c, alphabetical tie-break puts a first.
	assert.Equal(t, "a", got[1].Name)
	assert.Equal(t, "c", got[2].Name)
}

func TestPrecedenceCycleRejected(t *testing.T) {
	db := testDB(t)
	g, _ := db.CreateGroup(nil, "g")
	a, _ := db.CreatePolicy("a", []string{"*"}, []string{"*"}, []string{"*"})
	b, _ := db.CreatePolicy("b", []string{"*"}, []string{"*"}, []string{"*"})
	db.AttachPolicy(g.ID(), a.ID)
	db.AttachPolicy(g.ID(), b.ID)

	// a depends on b (fine).
	require.Nil(t, db.AddPrecedence(g.ID(), a.ID, b.ID))
	// Now b depends on a — would close a cycle. Must be rejected.
	err := db.AddPrecedence(g.ID(), b.ID, a.ID)
	require.NotNil(t, err)
}

func TestPrecedenceSelfLoopRejected(t *testing.T) {
	db := testDB(t)
	g, _ := db.CreateGroup(nil, "g")
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	db.AttachPolicy(g.ID(), p.ID)
	err := db.AddPrecedence(g.ID(), p.ID, p.ID)
	require.NotNil(t, err)
}

func TestDetachCascadesPrecedence(t *testing.T) {
	db := testDB(t)
	g, _ := db.CreateGroup(nil, "g")
	a, _ := db.CreatePolicy("a", []string{"*"}, []string{"*"}, []string{"*"})
	b, _ := db.CreatePolicy("b", []string{"*"}, []string{"*"}, []string{"*"})
	db.AttachPolicy(g.ID(), a.ID)
	db.AttachPolicy(g.ID(), b.ID)
	db.AddPrecedence(g.ID(), a.ID, b.ID)

	// Detach b — any edges touching it should be cascaded away.
	require.Nil(t, db.DetachPolicy(g.ID(), b.ID))

	edges, err := db.ListNodePolicyPrecedence(g.ID())
	require.Nil(t, err)
	assert.Equal(t, 0, len(edges))
}

func TestListNodesReferencingPolicy(t *testing.T) {
	db := testDB(t)
	p, _ := db.CreatePolicy("p", []string{"*"}, []string{"*"}, []string{"*"})
	g1, _ := db.CreateGroup(nil, "g1")
	g2, _ := db.CreateGroup(nil, "g2")
	db.AttachPolicy(g1.ID(), p.ID)
	db.AttachPolicy(g2.ID(), p.ID)

	nodes, err := db.ListNodesReferencingPolicy(p.ID)
	require.Nil(t, err)
	assert.Equal(t, 2, len(nodes))

	cnt, err := db.CountNodesReferencingPolicy(p.ID)
	require.Nil(t, err)
	assert.Equal(t, int64(2), cnt)
}

// --- Legacy migration ---

func TestMigrateLegacySchema(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)

	dbPath := t.TempDir() + "/legacy.db"

	rawDB, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	require.Nil(t, err)

	// Set up the latest flavor of the legacy schema: environment_id FKs +
	// plural JSON pattern columns.
	_, err = rawDB.Exec(`
		CREATE TABLE environments (
			id TEXT PRIMARY KEY,
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(project, environment)
		);
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY,
			key TEXT NOT NULL,
			value BLOB NOT NULL,
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(key, environment_id)
		);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			repository_patterns TEXT NOT NULL DEFAULT '[]',
			ref_patterns TEXT NOT NULL DEFAULT '["*"]',
			actor_patterns TEXT NOT NULL DEFAULT '["*"]',
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
	`)
	require.Nil(t, err)

	_, err = rawDB.Exec(`INSERT INTO environments (id, project, environment) VALUES ('env-prod', 'myapp', 'prod')`)
	require.Nil(t, err)
	_, err = rawDB.Exec(`INSERT INTO environments (id, project, environment) VALUES ('env-stg',  'myapp', 'staging')`)
	require.Nil(t, err)

	encrypted, err := enc.Encrypt([]byte("the-prod-value"))
	require.Nil(t, err)
	b64Prod := base64.StdEncoding.EncodeToString(encrypted)

	encrypted, err = enc.Encrypt([]byte("the-staging-value"))
	require.Nil(t, err)
	b64Stg := base64.StdEncoding.EncodeToString(encrypted)

	_, err = rawDB.Exec(`INSERT INTO secrets (id, key, value, environment_id) VALUES ('s1', 'DATABASE_URL', ?, 'env-prod')`, b64Prod)
	require.Nil(t, err)
	_, err = rawDB.Exec(`INSERT INTO secrets (id, key, value, environment_id) VALUES ('s2', 'DATABASE_URL', ?, 'env-stg')`, b64Stg)
	require.Nil(t, err)

	// Policy with non-empty repository + ref, and empty actor (legacy "[]").
	_, err = rawDB.Exec(`INSERT INTO access_policies (id, name, repository_patterns, ref_patterns, actor_patterns, environment_id)
		VALUES ('p1', 'allow-prod', '["myorg/*"]', '["refs/heads/main"]', '[]', 'env-prod')`)
	require.Nil(t, err)

	rawDB.Close()

	// Open with New() — triggers migration.
	db, err := New(dbPath, enc)
	require.Nil(t, err)
	defer db.Close()

	// Every old secret row should become a loose root-level leaf with the
	// project-environment-key name prefix.
	s1, err := db.GetSecret("s1")
	require.Nil(t, err)
	require.NotNil(t, s1)
	assert.Equal(t, "myapp-prod-DATABASE_URL", s1.Name())
	assert.Nil(t, s1.ParentID())
	assert.Equal(t, "the-prod-value", s1.Value)

	s2, err := db.GetSecret("s2")
	require.Nil(t, err)
	require.NotNil(t, s2)
	assert.Equal(t, "myapp-staging-DATABASE_URL", s2.Name())

	// Both secrets coexist in the same server because the prefixes make
	// their names globally unique.
	ctx := context.Background()
	count, err := db.Q().CountNodesByKind(ctx, "secret")
	require.Nil(t, err)
	assert.Equal(t, int64(2), count)

	// No groups created from migration.
	count, err = db.Q().CountNodesByKind(ctx, "group")
	require.Nil(t, err)
	assert.Equal(t, int64(0), count)

	// Policy preserved with patterns normalized; empty actor array means
	// zero actor rows (no wildcard synthesis).
	p, err := db.GetPolicy("p1")
	require.Nil(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "allow-prod", p.Name)
	assert.Equal(t, []string{"myorg/*"}, p.RepositoryPatterns)
	assert.Equal(t, []string{"refs/heads/main"}, p.RefPatterns)
	assert.Nil(t, p.ActorPatterns)

	// No attachments were migrated.
	ids, err := db.MatchingPolicyIDs(ctx, "myorg/repo", "refs/heads/main", "anyone")
	require.Nil(t, err)
	// The policy has zero actor patterns so nothing matches.
	assert.Equal(t, 0, len(ids))
}

func TestMigrateLegacyOldestSchema(t *testing.T) {
	// Even older flavor: secrets had project/environment columns directly
	// (no environment_id FK) and policies had singular pattern columns.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)

	dbPath := t.TempDir() + "/oldest.db"
	rawDB, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	require.Nil(t, err)

	_, err = rawDB.Exec(`
		CREATE TABLE environments (
			id TEXT PRIMARY KEY,
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(project, environment)
		);
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY,
			key TEXT NOT NULL,
			value BLOB NOT NULL,
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			repository_pattern TEXT NOT NULL,
			ref_pattern TEXT NOT NULL DEFAULT '*',
			actor_pattern TEXT NOT NULL DEFAULT '*',
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
	`)
	require.Nil(t, err)

	encrypted, err := enc.Encrypt([]byte("val"))
	require.Nil(t, err)
	b64 := base64.StdEncoding.EncodeToString(encrypted)

	// Seed an environments row so the migration's JOIN finds something for
	// this secret.
	_, err = rawDB.Exec(`INSERT INTO environments (id, project, environment) VALUES ('e1', 'proj', 'env')`)
	require.Nil(t, err)
	_, err = rawDB.Exec(`INSERT INTO secrets (id, key, value, project, environment) VALUES ('s1', 'K', ?, 'proj', 'env')`, b64)
	require.Nil(t, err)
	_, err = rawDB.Exec(`INSERT INTO access_policies (id, name, repository_pattern, ref_pattern, actor_pattern, project, environment) VALUES ('p1', 'allow', 'org/*', 'refs/heads/main', '*', 'proj', 'env')`)
	require.Nil(t, err)

	rawDB.Close()

	db, err := New(dbPath, enc)
	require.Nil(t, err)
	defer db.Close()

	s, err := db.GetSecret("s1")
	require.Nil(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "proj-env-K", s.Name())
	assert.Equal(t, "val", s.Value)

	p, err := db.GetPolicy("p1")
	require.Nil(t, err)
	require.NotNil(t, p)
	assert.Equal(t, []string{"org/*"}, p.RepositoryPatterns)
	assert.Equal(t, []string{"refs/heads/main"}, p.RefPatterns)
	assert.Equal(t, []string{"*"}, p.ActorPatterns)
}
