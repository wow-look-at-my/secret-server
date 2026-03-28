package database

import (
	"os"
	"testing"

	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
)

func testAuditDB(t *testing.T) *AuditDB {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "test-audit-*.db")
	require.Nil(t, err)
	f.Close()
	db, err := NewAuditDB(f.Name())
	require.Nil(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAuditCreateAndList(t *testing.T) {
	db := testAuditDB(t)

	err := db.CreateEntry("secret.create", "admin", "user@test.com", "secret", "abc123", `{"key":"API_KEY"}`)
	require.Nil(t, err)

	err = db.CreateEntry("secret.delete", "admin", "user@test.com", "secret", "abc123", "{}")
	require.Nil(t, err)

	entries, err := db.ListEntries(10, 0)
	require.Nil(t, err)
	require.Equal(t, 2, len(entries))

	// Newest first
	assert.Equal(t, "secret.delete", entries[0].Action)
	assert.Equal(t, "secret.create", entries[1].Action)
	assert.Equal(t, "admin", entries[0].ActorType)
	assert.Equal(t, "user@test.com", entries[0].ActorID)
	assert.Equal(t, "secret", entries[0].ResourceType)
	assert.Equal(t, "abc123", entries[0].ResourceID)
}

func TestAuditCount(t *testing.T) {
	db := testAuditDB(t)

	count, err := db.CountEntries()
	require.Nil(t, err)
	assert.Equal(t, 0, count)

	db.CreateEntry("secret.create", "admin", "user@test.com", "secret", "id1", "{}")
	db.CreateEntry("policy.create", "admin", "user@test.com", "policy", "id2", "{}")

	count, err = db.CountEntries()
	require.Nil(t, err)
	assert.Equal(t, 2, count)
}

func TestAuditPagination(t *testing.T) {
	db := testAuditDB(t)

	for i := 0; i < 5; i++ {
		db.CreateEntry("secret.create", "admin", "user@test.com", "secret", "", "{}")
	}

	entries, err := db.ListEntries(3, 0)
	require.Nil(t, err)
	assert.Equal(t, 3, len(entries))

	entries, err = db.ListEntries(3, 3)
	require.Nil(t, err)
	assert.Equal(t, 2, len(entries))

	entries, err = db.ListEntries(3, 10)
	require.Nil(t, err)
	assert.Equal(t, 0, len(entries))
}

func TestAuditDefaultLimit(t *testing.T) {
	db := testAuditDB(t)
	db.CreateEntry("test", "admin", "user@test.com", "secret", "", "{}")

	// Passing 0 should use default limit of 50
	entries, err := db.ListEntries(0, 0)
	require.Nil(t, err)
	assert.Equal(t, 1, len(entries))
}
