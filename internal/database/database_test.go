package database

import (
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

	// Exists
	exists, err := db.EnvironmentExists("myapp", "prod")
	require.Nil(t, err)
	assert.True(t, exists)

	exists, err = db.EnvironmentExists("myapp", "staging")
	require.Nil(t, err)
	assert.False(t, exists)

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

func TestEnvironmentInUse(t *testing.T) {
	db := testDB(t)
	env, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	// Not in use initially
	inUse, err := db.EnvironmentInUse("myapp", "prod")
	require.Nil(t, err)
	assert.False(t, inUse)

	// Create a secret referencing it
	_, err = db.CreateSecret("KEY", "val", "myapp", "prod")
	require.Nil(t, err)

	inUse, err = db.EnvironmentInUse("myapp", "prod")
	require.Nil(t, err)
	assert.True(t, inUse)

	// Clean up secret so we can test with policy
	secrets, _ := db.ListSecrets("myapp", "prod")
	db.DeleteSecret(secrets[0].ID)

	// Create a policy referencing it
	_, err = db.CreatePolicy("p1", "*", "*", "myapp", "prod")
	require.Nil(t, err)

	inUse, err = db.EnvironmentInUse("myapp", "prod")
	require.Nil(t, err)
	assert.True(t, inUse)

	_ = env
}

func TestEnvironmentValidation(t *testing.T) {
	db := testDB(t)

	// Creating a secret without a matching environment should fail
	_, err := db.CreateSecret("KEY", "val", "myapp", "prod")
	require.NotNil(t, err)
	assert.ErrorIs(t, err, ErrInvalidEnvironment)

	// Creating a policy without a matching environment should fail
	_, err = db.CreatePolicy("p1", "*", "*", "myapp", "prod")
	require.NotNil(t, err)
	assert.ErrorIs(t, err, ErrInvalidEnvironment)

	// Create the environment, then it should work
	_, err = db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	_, err = db.CreateSecret("KEY", "val", "myapp", "prod")
	require.Nil(t, err)

	_, err = db.CreatePolicy("p1", "*", "*", "myapp", "prod")
	require.Nil(t, err)
}

func TestSecretCRUD(t *testing.T) {
	db := testDB(t)

	// Set up environments first
	_, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	// Create
	s, err := db.CreateSecret("API_KEY", "secret123", "myapp", "prod")
	require.Nil(t, err)
	require.NotEqual(t, "", s.ID)
	assert.Equal(t, "API_KEY", s.Key)

	// Get
	got, err := db.GetSecret(s.ID)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "secret123", got.Value)
	assert.Equal(t, "myapp", got.Project)

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
	err = db.UpdateSecret(s.ID, "API_KEY", "newsecret", "myapp", "prod")
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
	_, err := db.CreateEnvironment("proj", "env")
	require.Nil(t, err)

	_, err = db.CreateSecret("KEY", "val1", "proj", "env")
	require.Nil(t, err)

	_, err = db.CreateSecret("KEY", "val2", "proj", "env")
	require.NotNil(t, err)
}

func TestGetSecretsByProjectEnv(t *testing.T) {
	db := testDB(t)
	_, err := db.CreateEnvironment("proj", "prod")
	require.Nil(t, err)
	_, err = db.CreateEnvironment("proj", "dev")
	require.Nil(t, err)
	_, err = db.CreateEnvironment("other", "prod")
	require.Nil(t, err)

	db.CreateSecret("A", "1", "proj", "prod")
	db.CreateSecret("B", "2", "proj", "prod")
	db.CreateSecret("C", "3", "proj", "dev")
	db.CreateSecret("D", "4", "other", "prod")

	secrets, err := db.GetSecretsByProjectEnv("proj", "prod")
	require.Nil(t, err)
	require.Equal(t, 2, len(secrets))
	assert.False(t, secrets["A"] != "1" || secrets["B"] != "2")
}

func TestPolicyCRUD(t *testing.T) {
	db := testDB(t)

	// Set up environments first
	_, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)
	_, err = db.CreateEnvironment("myapp", "staging")
	require.Nil(t, err)

	// Create
	p, err := db.CreatePolicy("Allow prod", "myorg/*", "refs/heads/main", "myapp", "prod")
	require.Nil(t, err)
	require.NotEqual(t, "", p.ID)

	// Get
	got, err := db.GetPolicy(p.ID)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "Allow prod", got.Name)
	assert.Equal(t, "myorg/*", got.RepositoryPattern)

	// List
	policies, err := db.ListPolicies()
	require.Nil(t, err)
	require.Equal(t, 1, len(policies))

	// Update
	err = db.UpdatePolicy(p.ID, "Updated", "other/*", "*", "myapp", "staging")
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
	_, err := db.CreateEnvironment("app", "prod")
	require.Nil(t, err)
	_, err = db.CreateEnvironment("app", "dev")
	require.Nil(t, err)
	_, err = db.CreateEnvironment("other", "prod")
	require.Nil(t, err)

	db.CreatePolicy("p1", "myorg/*", "refs/heads/main", "app", "prod")
	db.CreatePolicy("p2", "myorg/specific", "*", "app", "dev")
	db.CreatePolicy("p3", "other/*", "*", "other", "prod")

	// Should match p1 only
	matched, err := db.MatchingPolicies("myorg/repo", "refs/heads/main")
	require.Nil(t, err)
	assert.False(t, len(matched) != 1 || matched[0].Name != "p1")

	// Should match p1 and p2
	matched, err = db.MatchingPolicies("myorg/specific", "refs/heads/main")
	require.Nil(t, err)
	assert.Equal(t, 2, len(matched))

	// No match
	matched, err = db.MatchingPolicies("unknown/repo", "refs/heads/main")
	require.Nil(t, err)
	assert.Equal(t, 0, len(matched))
}

func TestDashboardStats(t *testing.T) {
	db := testDB(t)
	_, err := db.CreateEnvironment("proj", "prod")
	require.Nil(t, err)
	_, err = db.CreateEnvironment("proj", "dev")
	require.Nil(t, err)

	db.CreateSecret("A", "1", "proj", "prod")
	db.CreateSecret("B", "2", "proj", "prod")
	db.CreateSecret("C", "3", "proj", "dev")
	db.CreatePolicy("p1", "*", "*", "proj", "prod")

	stats, err := db.GetDashboardStats()
	require.Nil(t, err)
	assert.Equal(t, 3, stats.TotalSecrets)
	assert.Equal(t, 1, stats.TotalPolicies)
	assert.Equal(t, 2, stats.TotalEnvironments)
	assert.Equal(t, 2, len(stats.Projects))
}

func TestSeedEnvironments(t *testing.T) {
	// Test that existing data is seeded into environments table on migration.
	// We can't easily test this with a fresh DB since there's no data to seed.
	// But we can verify the seed function is idempotent.
	db := testDB(t)
	_, err := db.CreateEnvironment("proj", "prod")
	require.Nil(t, err)

	// Running seed again should not fail or create duplicates
	err = db.seedEnvironments()
	require.Nil(t, err)

	envs, err := db.ListEnvironments()
	require.Nil(t, err)
	assert.Equal(t, 1, len(envs))
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
	_, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	s, err := db.CreateSecret("KEY", "val", "myapp", "prod")
	require.Nil(t, err)

	// Updating to a non-existent environment should fail
	err = db.UpdateSecret(s.ID, "KEY", "val", "myapp", "nonexistent")
	assert.ErrorIs(t, err, ErrInvalidEnvironment)
}

func TestUpdatePolicyInvalidEnvironment(t *testing.T) {
	db := testDB(t)
	_, err := db.CreateEnvironment("myapp", "prod")
	require.Nil(t, err)

	p, err := db.CreatePolicy("p1", "*", "*", "myapp", "prod")
	require.Nil(t, err)

	err = db.UpdatePolicy(p.ID, "p1", "*", "*", "myapp", "nonexistent")
	assert.ErrorIs(t, err, ErrInvalidEnvironment)
}
