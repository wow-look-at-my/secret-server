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

func TestSecretCRUD(t *testing.T) {
	db := testDB(t)

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
	_, err := db.CreateSecret("KEY", "val1", "proj", "env")
	require.Nil(t, err)

	_, err = db.CreateSecret("KEY", "val2", "proj", "env")
	require.NotNil(t, err)

}

func TestGetSecretsByProjectEnv(t *testing.T) {
	db := testDB(t)
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
	db.CreateSecret("A", "1", "proj", "prod")
	db.CreateSecret("B", "2", "proj", "prod")
	db.CreateSecret("C", "3", "proj", "dev")
	db.CreatePolicy("p1", "*", "*", "proj", "prod")

	stats, err := db.GetDashboardStats()
	require.Nil(t, err)

	assert.Equal(t, 3, stats.TotalSecrets)

	assert.Equal(t, 1, stats.TotalPolicies)

	assert.Equal(t, 2, len(stats.Projects))

}
