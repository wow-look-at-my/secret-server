package sqlcdb_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sqlcdb.Queries {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(on)")
	require.Nil(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
		CREATE TABLE environments (
			id TEXT PRIMARY KEY, project TEXT NOT NULL, environment TEXT NOT NULL,
			created_at DATETIME NOT NULL, UNIQUE(project, environment)
		);
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY, key TEXT NOT NULL, value BLOB NOT NULL,
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
			UNIQUE(key, environment_id)
		);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			repository_pattern TEXT NOT NULL, ref_pattern TEXT NOT NULL DEFAULT '*',
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL
		);
		CREATE INDEX idx_secrets_env_id ON secrets(environment_id);
		CREATE INDEX idx_policies_env_id ON access_policies(environment_id);
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

// createEnv is a test helper to create an environment and return its ID.
func createEnv(t *testing.T, q *sqlcdb.Queries, id, project, env string) {
	t.Helper()
	err := q.CreateEnvironment(context.Background(), sqlcdb.CreateEnvironmentParams{
		ID: id, Project: project, Environment: env, CreatedAt: time.Now().UTC(),
	})
	require.Nil(t, err)
}

func TestSecretQueries(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create environments first (FK requirement)
	createEnv(t, q, "env-proj-prod", "proj", "prod")
	createEnv(t, q, "env-proj-dev", "proj", "dev")
	createEnv(t, q, "env-other-prod", "other", "prod")

	// Create secrets
	err := q.CreateSecret(ctx, sqlcdb.CreateSecretParams{
		ID: "s1", Key: "KEY_A", Value: []byte("enc1"),
		EnvironmentID: "env-proj-prod", CreatedAt: now, UpdatedAt: now,
	})
	require.Nil(t, err)

	err = q.CreateSecret(ctx, sqlcdb.CreateSecretParams{
		ID: "s2", Key: "KEY_B", Value: []byte("enc2"),
		EnvironmentID: "env-proj-dev", CreatedAt: now, UpdatedAt: now,
	})
	require.Nil(t, err)

	err = q.CreateSecret(ctx, sqlcdb.CreateSecretParams{
		ID: "s3", Key: "KEY_C", Value: []byte("enc3"),
		EnvironmentID: "env-other-prod", CreatedAt: now, UpdatedAt: now,
	})
	require.Nil(t, err)

	// Get
	s, err := q.GetSecret(ctx, "s1")
	require.Nil(t, err)
	assert.Equal(t, "KEY_A", s.Key)
	assert.Equal(t, "proj", s.Project)
	assert.Equal(t, "prod", s.Environment)
	assert.Equal(t, "env-proj-prod", s.EnvironmentID)

	// ListSecretsAll
	all, err := q.ListSecretsAll(ctx)
	require.Nil(t, err)
	assert.Equal(t, 3, len(all))

	// ListSecretsByProject
	byProj, err := q.ListSecretsByProject(ctx, "proj")
	require.Nil(t, err)
	assert.Equal(t, 2, len(byProj))

	// ListSecretsByEnv
	byEnv, err := q.ListSecretsByEnv(ctx, "prod")
	require.Nil(t, err)
	assert.Equal(t, 2, len(byEnv))

	// ListSecretsByProjectAndEnv
	byBoth, err := q.ListSecretsByProjectAndEnv(ctx, sqlcdb.ListSecretsByProjectAndEnvParams{
		Project: "proj", Environment: "prod",
	})
	require.Nil(t, err)
	assert.Equal(t, 1, len(byBoth))

	// GetSecretsByEnvironmentID
	kv, err := q.GetSecretsByEnvironmentID(ctx, "env-proj-prod")
	require.Nil(t, err)
	assert.Equal(t, 1, len(kv))
	assert.Equal(t, "KEY_A", kv[0].Key)

	// Update
	result, err := q.UpdateSecret(ctx, sqlcdb.UpdateSecretParams{
		Key: "KEY_A", Value: []byte("updated"),
		EnvironmentID: "env-proj-prod", UpdatedAt: now, ID: "s1",
	})
	require.Nil(t, err)
	n, _ := result.RowsAffected()
	assert.Equal(t, int64(1), n)

	// Delete
	result, err = q.DeleteSecret(ctx, "s1")
	require.Nil(t, err)
	n, _ = result.RowsAffected()
	assert.Equal(t, int64(1), n)

	// CountSecrets
	count, err := q.CountSecrets(ctx)
	require.Nil(t, err)
	assert.Equal(t, int64(2), count)

	// SecretCountsByProjectEnv
	stats, err := q.SecretCountsByProjectEnv(ctx)
	require.Nil(t, err)
	assert.Equal(t, 2, len(stats))
}

func TestEnvironmentQueries(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	err := q.CreateEnvironment(ctx, sqlcdb.CreateEnvironmentParams{
		ID: "e1", Project: "proj", Environment: "prod", CreatedAt: now,
	})
	require.Nil(t, err)

	env, err := q.GetEnvironment(ctx, "e1")
	require.Nil(t, err)
	assert.Equal(t, "proj", env.Project)

	envs, err := q.ListEnvironments(ctx)
	require.Nil(t, err)
	assert.Equal(t, 1, len(envs))

	count, err := q.CountEnvironments(ctx)
	require.Nil(t, err)
	assert.Equal(t, int64(1), count)

	// InsertEnvironmentIgnore (duplicate should not error)
	err = q.InsertEnvironmentIgnore(ctx, sqlcdb.InsertEnvironmentIgnoreParams{
		ID: "e2", Project: "proj", Environment: "prod",
	})
	require.Nil(t, err)

	// Verify no duplicate was created
	envs, err = q.ListEnvironments(ctx)
	require.Nil(t, err)
	assert.Equal(t, 1, len(envs))

	// UpdateEnvironment
	result, err := q.UpdateEnvironment(ctx, sqlcdb.UpdateEnvironmentParams{
		Project: "proj-renamed", Environment: "production", ID: "e1",
	})
	require.Nil(t, err)
	n, _ := result.RowsAffected()
	assert.Equal(t, int64(1), n)

	env, err = q.GetEnvironment(ctx, "e1")
	require.Nil(t, err)
	assert.Equal(t, "proj-renamed", env.Project)

	// EnvironmentInUseSecrets (no secrets yet)
	count, err = q.EnvironmentInUseSecrets(ctx, "e1")
	require.Nil(t, err)
	assert.Equal(t, int64(0), count)

	// EnvironmentInUsePolicies (no policies yet)
	count, err = q.EnvironmentInUsePolicies(ctx, "e1")
	require.Nil(t, err)
	assert.Equal(t, int64(0), count)

	// Delete
	delResult, err := q.DeleteEnvironment(ctx, "e1")
	require.Nil(t, err)
	n, _ = delResult.RowsAffected()
	assert.Equal(t, int64(1), n)
}

func TestPolicyQueries(t *testing.T) {
	q := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create environment first (FK requirement)
	createEnv(t, q, "env-1", "proj", "prod")

	err := q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{
		ID: "p1", Name: "Allow prod", RepositoryPattern: "org/*",
		RefPattern: "refs/heads/main", EnvironmentID: "env-1",
		CreatedAt: now,
	})
	require.Nil(t, err)

	p, err := q.GetPolicy(ctx, "p1")
	require.Nil(t, err)
	assert.Equal(t, "Allow prod", p.Name)
	assert.Equal(t, "proj", p.Project)
	assert.Equal(t, "prod", p.Environment)
	assert.Equal(t, "env-1", p.EnvironmentID)

	policies, err := q.ListPolicies(ctx)
	require.Nil(t, err)
	assert.Equal(t, 1, len(policies))

	count, err := q.CountPolicies(ctx)
	require.Nil(t, err)
	assert.Equal(t, int64(1), count)

	result, err := q.UpdatePolicy(ctx, sqlcdb.UpdatePolicyParams{
		Name: "Updated", RepositoryPattern: "other/*", RefPattern: "*",
		EnvironmentID: "env-1", ID: "p1",
	})
	require.Nil(t, err)
	n, _ := result.RowsAffected()
	assert.Equal(t, int64(1), n)

	result, err = q.DeletePolicy(ctx, "p1")
	require.Nil(t, err)
	n, _ = result.RowsAffected()
	assert.Equal(t, int64(1), n)
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
