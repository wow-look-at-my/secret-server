package database

import (
	"database/sql"
	"encoding/base64"
	"os"
	"testing"

	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
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

func TestEnvironmentCRUD(t *testing.T) {
	db := testDB(t)

	// Create
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)
	require.NotEqual(t, "", env.ID)
	assert.Equal(t, "myapp", env.Project)
	assert.Equal(t, "prod", env.Environment)

	// Get
	got, err := db.GetEnvironment(env.ID)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "myapp", got.Project)

	// List
	envs, err := db.ListEnvironments()
	require.Nil(t, err)
	require.Equal(t, 1, len(envs))

	// Duplicate should fail
	_, err = db.CreateEnvironment("myapp", "prod")
	require.NotNil(t, err)

	// Delete
	err = db.DeleteEnvironment(env.ID)
	require.Nil(t, err)

	got, err = db.GetEnvironment(env.ID)
	require.Nil(t, err)
	require.Nil(t, got)
}

func TestUpdateEnvironment(t *testing.T) {
	db := testDB(t)

	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	// Create a secret referencing this environment
	_, err = db.CreateSecret("KEY", "val", env.ID)
	require.Nil(t, err)

	// Rename the environment
	err = db.UpdateEnvironment(env.ID, "myapp-renamed", "production")
	require.Nil(t, err)

	// Verify the environment is renamed
	got, err := db.GetEnvironment(env.ID)
	require.Nil(t, err)
	assert.Equal(t, "myapp-renamed", got.Project)
	assert.Equal(t, "production", got.Environment)

	// Verify the secret reflects the new name via JOIN
	secrets, err := db.ListSecrets("myapp-renamed", "production")
	require.Nil(t, err)
	require.Equal(t, 1, len(secrets))
	assert.Equal(t, "KEY", secrets[0].Key)
	assert.Equal(t, "myapp-renamed", secrets[0].Project)
	assert.Equal(t, "production", secrets[0].Environment)

	// Old name should return nothing
	secrets, err = db.ListSecrets("myapp", "prod")
	require.Nil(t, err)
	assert.Equal(t, 0, len(secrets))
}

func TestUpdateEnvironmentDuplicate(t *testing.T) {
	db := testDB(t)

	_, err := db.CreateEnvironment("app", "prod")
	require.Nil(t, err)
	env2, err := db.CreateEnvironment("app", "staging")
	require.Nil(t, err)

	// Renaming staging to prod should fail (duplicate)
	err = db.UpdateEnvironment(env2.ID, "app", "prod")
	require.NotNil(t, err)
}

func TestUpdateEnvironmentNotFound(t *testing.T) {
	db := testDB(t)
	err := db.UpdateEnvironment("nonexistent", "app", "prod")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestEnvironmentInUse(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	// Not in use initially
	inUse, err := db.EnvironmentInUse(env.ID)
	require.Nil(t, err)
	assert.False(t, inUse)

	// Create a secret referencing it
	s, err := db.CreateSecret("KEY", "val", env.ID)
	require.Nil(t, err)

	inUse, err = db.EnvironmentInUse(env.ID)
	require.Nil(t, err)
	assert.True(t, inUse)

	// Clean up secret so we can test with policy
	db.DeleteSecret(s.ID)

	// Create a policy referencing it
	_, err = db.CreatePolicy("p1", "*", "*", "*", env.ID)
	require.Nil(t, err)

	inUse, err = db.EnvironmentInUse(env.ID)
	require.Nil(t, err)
	assert.True(t, inUse)
}

func TestSecretFKConstraint(t *testing.T) {
	db := testDB(t)

	// Creating a secret with a non-existent environment_id should fail (FK)
	_, err := db.CreateSecret("KEY", "val", "nonexistent-env-id")
	require.NotNil(t, err)

	// Creating a policy with a non-existent environment_id should fail (FK)
	_, err = db.CreatePolicy("p1", "*", "*", "*", "nonexistent-env-id")
	require.NotNil(t, err)

	// Create the environment, then it should work
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	_, err = db.CreateSecret("KEY", "val", env.ID)
	require.Nil(t, err)

	_, err = db.CreatePolicy("p1", "*", "*", "*", env.ID)
	require.Nil(t, err)
}

func TestSecretCRUD(t *testing.T) {
	db := testDB(t)

	// Set up environments first
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	// Create
	s, err := db.CreateSecret("API_KEY", "secret123", env.ID)
	require.Nil(t, err)
	require.NotEqual(t, "", s.ID)
	assert.Equal(t, "API_KEY", s.Key)

	// Get
	got, err := db.GetSecret(s.ID)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "secret123", got.Value)
	assert.Equal(t, "myapp", got.Project)
	assert.Equal(t, env.ID, got.EnvironmentID)

	// List
	secrets, err := db.ListSecrets("", "")
	require.Nil(t, err)
	require.Equal(t, 1, len(secrets))

	// List with filter
	secrets, err = db.ListSecrets("myapp", "")
	require.Nil(t, err)
	require.Equal(t, 1, len(secrets))

	secrets, err = db.ListSecrets("other", "")
	require.Nil(t, err)
	require.Equal(t, 0, len(secrets))

	// Update
	err = db.UpdateSecret(s.ID, "API_KEY", "newsecret", env.ID)
	require.Nil(t, err)

	got, _ = db.GetSecret(s.ID)
	assert.Equal(t, "newsecret", got.Value)

	// Delete
	err = db.DeleteSecret(s.ID)
	require.Nil(t, err)

	got, err = db.GetSecret(s.ID)
	require.Nil(t, err)
	require.Nil(t, got)
}

func TestGetSecretNotFound(t *testing.T) {
	db := testDB(t)
	got, err := db.GetSecret("nonexistent")
	require.Nil(t, err)
	require.Nil(t, got)
}

func TestSecretUniqueConstraint(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("proj", "env")
	require.Nil(t, err)

	_, err = db.CreateSecret("KEY", "val1", env.ID)
	require.Nil(t, err)

	_, err = db.CreateSecret("KEY", "val2", env.ID)
	require.NotNil(t, err)
}

func TestGetSecretsByEnvironmentID(t *testing.T) {
	db := testDB(t)
	envProd, err := db.CreateEnvironment("proj", "prod")
	require.Nil(t, err)
	envDev, err := db.CreateEnvironment("proj", "dev")
	require.Nil(t, err)
	envOther, err := db.CreateEnvironment("other", "prod")
	require.Nil(t, err)

	db.CreateSecret("A", "1", envProd.ID)
	db.CreateSecret("B", "2", envProd.ID)
	db.CreateSecret("C", "3", envDev.ID)
	db.CreateSecret("D", "4", envOther.ID)

	secrets, err := db.GetSecretsByEnvironmentID(envProd.ID)
	require.Nil(t, err)
	require.Equal(t, 2, len(secrets))
	assert.False(t, secrets["A"] != "1" || secrets["B"] != "2")
}

func TestPolicyCRUD(t *testing.T) {
	db := testDB(t)

	// Set up environments first
	envProd, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)
	envStaging, err := db.CreateEnvironment("myapp", "staging")
	require.Nil(t, err)

	// Create
	p, err := db.CreatePolicy("Allow prod", "myorg/*", "refs/heads/main", "*", envProd.ID)
	require.Nil(t, err)
	require.NotEqual(t, "", p.ID)

	// Get
	got, err := db.GetPolicy(p.ID)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "Allow prod", got.Name)
	assert.Equal(t, "myorg/*", got.RepositoryPattern)
	assert.Equal(t, "myapp", got.Project)

	// List
	policies, err := db.ListPolicies()
	require.Nil(t, err)
	require.Equal(t, 1, len(policies))

	// Update
	err = db.UpdatePolicy(p.ID, "Updated", "other/*", "*", "*", envStaging.ID)
	require.Nil(t, err)

	got, _ = db.GetPolicy(p.ID)
	assert.Equal(t, "Updated", got.Name)
	assert.Equal(t, "staging", got.Environment)

	// Delete
	err = db.DeletePolicy(p.ID)
	require.Nil(t, err)

	got, err = db.GetPolicy(p.ID)
	require.Nil(t, err)
	require.Nil(t, got)
}

func TestGetPolicyNotFound(t *testing.T) {
	db := testDB(t)
	got, err := db.GetPolicy("nonexistent")
	require.Nil(t, err)
	require.Nil(t, got)
}

func TestMatchingPolicies(t *testing.T) {
	db := testDB(t)
	envProd, err := db.CreateEnvironment("app", "prod")
	require.Nil(t, err)
	envDev, err := db.CreateEnvironment("app", "dev")
	require.Nil(t, err)
	envOther, err := db.CreateEnvironment("other", "prod")
	require.Nil(t, err)

	db.CreatePolicy("p1", "myorg/*", "refs/heads/main", "*", envProd.ID)
	db.CreatePolicy("p2", "myorg/specific", "*", "*", envDev.ID)
	db.CreatePolicy("p3", "other/*", "*", "*", envOther.ID)

	// Should match p1 only
	matched, err := db.MatchingPolicies("myorg/repo", "refs/heads/main", "someone")
	require.Nil(t, err)
	assert.False(t, len(matched) != 1 || matched[0].Name != "p1")

	// Should match p1 and p2
	matched, err = db.MatchingPolicies("myorg/specific", "refs/heads/main", "someone")
	require.Nil(t, err)
	assert.Equal(t, 2, len(matched))

	// No match
	matched, err = db.MatchingPolicies("unknown/repo", "refs/heads/main", "someone")
	require.Nil(t, err)
	assert.Equal(t, 0, len(matched))
}

func TestMatchingPoliciesActorFilter(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("app", "prod")
	require.Nil(t, err)

	db.CreatePolicy("deployers-only", "myorg/*", "*", "deploy-*", env.ID)

	// Actor matches glob
	matched, err := db.MatchingPolicies("myorg/repo", "refs/heads/main", "deploy-bot")
	require.Nil(t, err)
	assert.Equal(t, 1, len(matched))

	// Actor does not match glob
	matched, err = db.MatchingPolicies("myorg/repo", "refs/heads/main", "random-user")
	require.Nil(t, err)
	assert.Equal(t, 0, len(matched))

	// Wildcard actor pattern matches anyone
	db.CreatePolicy("open", "myorg/*", "*", "*", env.ID)
	matched, err = db.MatchingPolicies("myorg/repo", "refs/heads/main", "random-user")
	require.Nil(t, err)
	assert.Equal(t, 1, len(matched))
}

func TestDashboardStats(t *testing.T) {
	db := testDB(t)
	envProd, err := db.CreateEnvironment("proj", "prod")
	require.Nil(t, err)
	envDev, err := db.CreateEnvironment("proj", "dev")
	require.Nil(t, err)

	db.CreateSecret("A", "1", envProd.ID)
	db.CreateSecret("B", "2", envProd.ID)
	db.CreateSecret("C", "3", envDev.ID)
	db.CreatePolicy("p1", "*", "*", "*", envProd.ID)

	stats, err := db.GetDashboardStats()
	require.Nil(t, err)
	assert.Equal(t, 3, stats.TotalSecrets)
	assert.Equal(t, 1, stats.TotalPolicies)
	assert.Equal(t, 2, stats.TotalEnvironments)
	assert.Equal(t, 2, len(stats.Projects))
}

func TestCountEnvironments(t *testing.T) {
	db := testDB(t)
	count, err := db.CountEnvironments()
	require.Nil(t, err)
	assert.Equal(t, 0, count)

	db.CreateEnvironment("a", "prod")
	db.CreateEnvironment("b", "staging")

	count, err = db.CountEnvironments()
	require.Nil(t, err)
	assert.Equal(t, 2, count)
}

func TestDeleteEnvironmentNotFound(t *testing.T) {
	db := testDB(t)
	err := db.DeleteEnvironment("nonexistent")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestUpdateSecretInvalidEnvironment(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	s, err := db.CreateSecret("KEY", "val", env.ID)
	require.Nil(t, err)

	// Updating to a non-existent environment_id should fail (FK)
	err = db.UpdateSecret(s.ID, "KEY", "val", "nonexistent-env-id")
	require.NotNil(t, err)
}

func TestUpdatePolicyInvalidEnvironment(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	p, err := db.CreatePolicy("p1", "*", "*", "*", env.ID)
	require.Nil(t, err)

	err = db.UpdatePolicy(p.ID, "p1", "*", "*", "*", "nonexistent-env-id")
	require.NotNil(t, err)
}

func TestMigrateFromOldSchema(t *testing.T) {
	// Create a database with the old schema (project/environment columns),
	// then open it with New() to trigger the migration.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)

	dbPath := t.TempDir() + "/migrate-test.db"

	// Create DB with old schema manually.
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
			updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(key, project, environment)
		);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			repository_pattern TEXT NOT NULL,
			ref_pattern TEXT NOT NULL DEFAULT '*',
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
	`)
	require.Nil(t, err)

	// Insert test data in old schema.
	_, err = rawDB.Exec(`INSERT INTO environments (id, project, environment) VALUES ('env-1', 'app', 'prod')`)
	require.Nil(t, err)

	encrypted, err := enc.Encrypt([]byte("secret-value"))
	require.Nil(t, err)
	encB64 := base64.StdEncoding.EncodeToString(encrypted)

	_, err = rawDB.Exec(`INSERT INTO secrets (id, key, value, project, environment) VALUES ('sec-1', 'API_KEY', ?, 'app', 'prod')`, encB64)
	require.Nil(t, err)
	_, err = rawDB.Exec(`INSERT INTO access_policies (id, name, repository_pattern, ref_pattern, project, environment) VALUES ('pol-1', 'allow', 'org/*', '*', 'app', 'prod')`)
	require.Nil(t, err)

	rawDB.Close()

	// Now open with New() — should trigger migration.
	db, err := New(dbPath, enc)
	require.Nil(t, err)
	defer db.Close()

	// Verify the migration worked: secrets and policies use environment_id.
	secret, err := db.GetSecret("sec-1")
	require.Nil(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, "API_KEY", secret.Key)
	assert.Equal(t, "secret-value", secret.Value)
	assert.Equal(t, "app", secret.Project)
	assert.Equal(t, "prod", secret.Environment)
	assert.Equal(t, "env-1", secret.EnvironmentID)

	policy, err := db.GetPolicy("pol-1")
	require.Nil(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "allow", policy.Name)
	assert.Equal(t, "app", policy.Project)
	assert.Equal(t, "prod", policy.Environment)
	assert.Equal(t, "env-1", policy.EnvironmentID)
	assert.Equal(t, "*", policy.ActorPattern)

	// Verify the environment is intact.
	env, err := db.GetEnvironment("env-1")
	require.Nil(t, err)
	require.NotNil(t, env)
	assert.Equal(t, "app", env.Project)
}

func TestMigrateActorPattern(t *testing.T) {
	// Create a database with the new schema but WITHOUT actor_pattern column,
	// then open it with New() to trigger the actor_pattern migration.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)

	dbPath := t.TempDir() + "/migrate-actor-test.db"

	rawDB, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	require.Nil(t, err)

	_, err = rawDB.Exec(`
		CREATE TABLE environments (
			id TEXT PRIMARY KEY, project TEXT NOT NULL, environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(project, environment)
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
			repository_pattern TEXT NOT NULL, ref_pattern TEXT NOT NULL DEFAULT '*',
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
		CREATE INDEX idx_secrets_env_id ON secrets(environment_id);
		CREATE INDEX idx_policies_env_id ON access_policies(environment_id);
	`)
	require.Nil(t, err)

	_, err = rawDB.Exec(`INSERT INTO environments (id, project, environment) VALUES ('env-1', 'app', 'prod')`)
	require.Nil(t, err)
	_, err = rawDB.Exec(`INSERT INTO access_policies (id, name, repository_pattern, ref_pattern, environment_id) VALUES ('pol-1', 'allow', 'org/*', '*', 'env-1')`)
	require.Nil(t, err)

	rawDB.Close()

	// Open with New() — should add actor_pattern column.
	db, err := New(dbPath, enc)
	require.Nil(t, err)
	defer db.Close()

	policy, err := db.GetPolicy("pol-1")
	require.Nil(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "*", policy.ActorPattern)
}
