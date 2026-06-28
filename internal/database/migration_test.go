package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
)

// Legacy-schema upgrade tests, split out of database_test.go to keep each
// file under the line cap.

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

	// Each old secret keeps its BARE key as the name. These two legacy rows
	// share the key DATABASE_URL, so the first (by key, project, environment
	// order — prod) keeps the clean name and only the colliding second one
	// (staging) is disambiguated.
	s1, err := db.GetSecret("s1")
	require.Nil(t, err)
	require.NotNil(t, s1)
	assert.Equal(t, "DATABASE_URL", s1.Name())
	assert.Nil(t, s1.ParentID())
	assert.Equal(t, "the-prod-value", s1.Value)

	s2, err := db.GetSecret("s2")
	require.Nil(t, err)
	require.NotNil(t, s2)
	assert.Equal(t, "DATABASE_URL-myapp-staging", s2.Name())

	// Both secrets coexist; the collision disambiguation keeps names unique.
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

	// Single secret with a unique key keeps its bare key as the name.
	s, err := db.GetSecret("s1")
	require.Nil(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "K", s.Name())
	assert.Equal(t, "val", s.Value)

	p, err := db.GetPolicy("p1")
	require.Nil(t, err)
	require.NotNil(t, p)
	assert.Equal(t, []string{"org/*"}, p.RepositoryPatterns)
	assert.Equal(t, []string{"refs/heads/main"}, p.RefPatterns)
	assert.Equal(t, []string{"*"}, p.ActorPatterns)
}

// TestMigrateLegacyKeepsBareKey pins the fix for the migration mangling secret
// names: a uniquely-keyed legacy secret must migrate to the exact same name a
// consumer references (e.g. the env-var name a workflow expects), NOT a
// project/environment-prefixed compound name.
func TestMigrateLegacyKeepsBareKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)

	dbPath := t.TempDir() + "/barekey.db"
	rawDB, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	require.Nil(t, err)

	_, err = rawDB.Exec(`
		CREATE TABLE environments (
			id TEXT PRIMARY KEY, project TEXT NOT NULL, environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')), UNIQUE(project, environment)
		);
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY, key TEXT NOT NULL, value BLOB NOT NULL,
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(key, environment_id)
		);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			repository_patterns TEXT NOT NULL DEFAULT '[]',
			ref_patterns TEXT NOT NULL DEFAULT '["*"]',
			actor_patterns TEXT NOT NULL DEFAULT '["*"]',
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
	`)
	require.Nil(t, err)

	// Mirror the real-world breakage: project "wow-look-at-my", environment
	// "low-risk", key "GO_BUILDCACHE_CONFIG" (both project and env contain
	// hyphens, which is exactly why the old prefix couldn't be reversed).
	_, err = rawDB.Exec(`INSERT INTO environments (id, project, environment) VALUES ('e1', 'wow-look-at-my', 'low-risk')`)
	require.Nil(t, err)
	encrypted, err := enc.Encrypt([]byte("cache-config-value"))
	require.Nil(t, err)
	b64 := base64.StdEncoding.EncodeToString(encrypted)
	_, err = rawDB.Exec(`INSERT INTO secrets (id, key, value, environment_id) VALUES ('s1', 'GO_BUILDCACHE_CONFIG', ?, 'e1')`, b64)
	require.Nil(t, err)
	rawDB.Close()

	db, err := New(dbPath, enc)
	require.Nil(t, err)
	defer db.Close()

	s, err := db.GetSecret("s1")
	require.Nil(t, err)
	require.NotNil(t, s)
	// The name is the bare key — NOT "wow-look-at-my-low-risk-GO_BUILDCACHE_CONFIG".
	assert.Equal(t, "GO_BUILDCACHE_CONFIG", s.Name())
	assert.Equal(t, "cache-config-value", s.Value)
}
