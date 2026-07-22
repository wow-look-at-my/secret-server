package database

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
)

// TestMigrateMachineTokensDropsPolicyColumn proves the upgrade path: a database
// created at the previous schema version (machine_tokens has a NOT NULL
// policy_id column bound to a policy) is rebuilt on open so machine tokens
// attach directly to nodes, with the token rows preserved.
func TestMigrateMachineTokensDropsPolicyColumn(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	require.Nil(t, err)

	dbPath := t.TempDir() + "/old.db"

	raw, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(on)")
	require.Nil(t, err)
	_, err = raw.Exec(`
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
		CREATE TABLE machine_tokens (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			token_hash   TEXT NOT NULL UNIQUE,
			token_prefix TEXT NOT NULL DEFAULT '',
			policy_id    TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
			created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
			last_used_at DATETIME
		);
		CREATE INDEX idx_machine_tokens_policy ON machine_tokens(policy_id);
		INSERT INTO access_policies (id, name) VALUES ('pol1', 'legacy');
	`)
	require.Nil(t, err)

	token := MachineTokenPrefix + "legacy-migration-token"
	_, err = raw.Exec(
		`INSERT INTO machine_tokens (id, name, token_hash, token_prefix, policy_id)
		 VALUES ('mt1', 'old-token', ?, 'sst_legacy', 'pol1')`,
		hashMachineToken(token),
	)
	require.Nil(t, err)
	require.Nil(t, raw.Close())

	// Opening through New runs migrate(), which relaxes policy_id to nullable.
	db, err := New(dbPath, enc)
	require.Nil(t, err)
	defer db.Close()

	// policy_id still exists, but is now nullable (optional).
	has, err := db.columnExists("machine_tokens", "policy_id")
	require.Nil(t, err)
	assert.True(t, has, "policy_id stays — it is now an optional binding")
	notNull, _, err := db.columnNotNull("machine_tokens", "policy_id")
	require.Nil(t, err)
	assert.False(t, notNull, "policy_id should be relaxed to nullable")

	// The token row survived the rebuild and kept its policy binding.
	got, err := db.LookupMachineToken(token)
	require.Nil(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "old-token", got.Name)
	require.NotNil(t, got.PolicyID)
	assert.Equal(t, "pol1", *got.PolicyID, "the legacy policy binding is preserved")

	// The preserved policy binding still vends: attach a secret to pol1 and the
	// token sees it through the union resolution.
	viaPolicy, err := db.CreateSecret(nil, "VIA_POLICY", "pv")
	require.Nil(t, err)
	require.Nil(t, db.AttachPolicy(viaPolicy.ID(), "pol1"))

	// And it can also attach directly to a secret via the new table.
	direct, err := db.CreateSecret(nil, "DIRECT", "dv")
	require.Nil(t, err)
	require.Nil(t, db.SetTokenNodes("mt1", []string{direct.ID()}))

	secrets, err := db.AuthorizedSecretsForToken(context.Background(), "mt1")
	require.Nil(t, err)
	assert.Equal(t, map[string]string{"VIA_POLICY": "pv", "DIRECT": "dv"}, secrets,
		"the token vends the union of its policy's secrets and its direct attachments")
}

// TestMigrateMachineTokensIdempotent ensures a current-schema database already
// has a nullable policy_id and that re-running migrate does not error.
func TestMigrateMachineTokensIdempotent(t *testing.T) {
	db := testDB(t)

	has, err := db.columnExists("machine_tokens", "policy_id")
	require.Nil(t, err)
	assert.True(t, has)
	notNull, _, err := db.columnNotNull("machine_tokens", "policy_id")
	require.Nil(t, err)
	assert.False(t, notNull, "a fresh DB's policy_id is nullable")

	require.Nil(t, db.migrate(), "migrate must be safe to re-run")
}
