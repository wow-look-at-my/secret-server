package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
)

// MachineTokenPrefix marks a bearer token as a machine token (as opposed to a
// GitHub OIDC JWT). It is part of the token string and lets the secrets
// endpoint pick the right validation path by inspecting the token, so both
// credential types can share one route. "sst" = secret-server token.
const MachineTokenPrefix = "sst_"

// machineTokenRandomBytes is the entropy in a freshly minted token (before the
// prefix). 32 bytes is far beyond brute-force reach for a bearer credential.
const machineTokenRandomBytes = 32

// MachineToken is a stored machine token. The secret token itself is never
// persisted — only its SHA-256 hash — so it cannot be recovered from the DB;
// it is shown to the operator exactly once, at creation. A token grants secrets
// by attaching directly to secret-tree nodes (see machine_token_nodes); it has
// no policy binding.
type MachineToken struct {
	ID          string
	Name        string
	TokenPrefix string // first chars of the token, for display ("sst_ab12…")
	CreatedAt   time.Time
	LastUsedAt  *time.Time // nil if never used
}

// TokenNode is a secret-tree node attached to a machine token. A "group" grants
// its whole subtree; a "secret" grants just that leaf.
type TokenNode struct {
	ID   string
	Kind string
	Name string
}

// hashMachineToken returns the hex-encoded SHA-256 of a token string. Tokens
// are high-entropy, so a fast hash with no per-row salt is sufficient: it
// prevents recovery of the token from the stored hash and makes lookups a
// simple indexed equality on the digest.
func hashMachineToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// generateMachineToken mints a new token string ("sst_<base64url>") and returns
// it together with its hash and a short display prefix.
func generateMachineToken() (token, hash, prefix string, err error) {
	buf := make([]byte, machineTokenRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("generate machine token: %w", err)
	}
	token = MachineTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	hash = hashMachineToken(token)
	prefix = token
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return token, hash, prefix, nil
}

// CreateMachineToken mints a token, attaches it to the given secret-tree nodes,
// and stores only its hash. Creation and attachment happen in one transaction,
// so a token never half-exists. The returned plaintext token is the only time
// it is ever available — the caller must surface it to the operator and then
// discard it. An unknown node ID fails the whole create with ErrNotFound.
func (d *DB) CreateMachineToken(name string, nodeIDs []string) (token string, rec *MachineToken, err error) {
	token, hash, prefix, err := generateMachineToken()
	if err != nil {
		return "", nil, err
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	ctx := context.Background()

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rolled back unless Commit succeeds
	q := d.q.WithTx(tx)

	if err := q.CreateMachineToken(ctx, sqlcdb.CreateMachineTokenParams{
		ID:          id,
		Name:        name,
		TokenHash:   hash,
		TokenPrefix: prefix,
		CreatedAt:   now,
	}); err != nil {
		return "", nil, fmt.Errorf("insert machine token: %w", err)
	}
	if err := attachNodesTx(ctx, q, id, nodeIDs); err != nil {
		return "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, fmt.Errorf("commit: %w", err)
	}
	return token, &MachineToken{
		ID:          id,
		Name:        name,
		TokenPrefix: prefix,
		CreatedAt:   now,
	}, nil
}

// SetTokenNodes replaces a token's attached nodes with exactly nodeIDs (clear
// then re-attach, in one transaction). An unknown node ID fails the whole
// update with ErrNotFound, leaving the prior attachments untouched.
func (d *DB) SetTokenNodes(tokenID string, nodeIDs []string) error {
	ctx := context.Background()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rolled back unless Commit succeeds
	q := d.q.WithTx(tx)

	if err := q.DeleteTokenNodes(ctx, tokenID); err != nil {
		return fmt.Errorf("clear token nodes: %w", err)
	}
	if err := attachNodesTx(ctx, q, tokenID, nodeIDs); err != nil {
		return err
	}
	return tx.Commit()
}

// attachNodesTx attaches each node to the token within a transaction, verifying
// the node exists first so an unknown ID is a clean ErrNotFound rather than a
// silent orphan row (or an opaque FK error). Attach is idempotent (INSERT OR
// IGNORE), so a repeated ID is harmless.
func attachNodesTx(ctx context.Context, q *sqlcdb.Queries, tokenID string, nodeIDs []string) error {
	for _, nid := range nodeIDs {
		if _, err := q.GetSecretNode(ctx, nid); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: secret node %q", ErrNotFound, nid)
			}
			return fmt.Errorf("look up node %q: %w", nid, err)
		}
		if err := q.AttachNodeToToken(ctx, sqlcdb.AttachNodeToTokenParams{
			TokenID: tokenID,
			NodeID:  nid,
		}); err != nil {
			return fmt.Errorf("attach node %q: %w", nid, err)
		}
	}
	return nil
}

// LookupMachineToken resolves a presented token to its stored record, or nil if
// no token matches (an unknown or revoked token). It does not distinguish
// "malformed" from "unknown" — both yield (nil, nil) — so callers return a
// single opaque 401 either way.
func (d *DB) LookupMachineToken(token string) (*MachineToken, error) {
	if !strings.HasPrefix(token, MachineTokenPrefix) {
		return nil, nil
	}
	row, err := d.q.GetMachineTokenByHash(context.Background(), hashMachineToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query machine token: %w", err)
	}
	return machineTokenFromRow(row.ID, row.Name, row.TokenPrefix, row.CreatedAt, row.LastUsedAt), nil
}

// GetMachineToken returns one token by ID, or nil if it doesn't exist.
func (d *DB) GetMachineToken(id string) (*MachineToken, error) {
	row, err := d.q.GetMachineToken(context.Background(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get machine token: %w", err)
	}
	return machineTokenFromRow(row.ID, row.Name, row.TokenPrefix, row.CreatedAt, row.LastUsedAt), nil
}

// machineTokenFromRow builds a MachineToken from the columns every token query
// returns, normalizing the nullable last_used_at.
func machineTokenFromRow(id, name, prefix string, createdAt time.Time, lastUsed sql.NullTime) *MachineToken {
	rec := &MachineToken{ID: id, Name: name, TokenPrefix: prefix, CreatedAt: createdAt}
	if lastUsed.Valid {
		t := lastUsed.Time
		rec.LastUsedAt = &t
	}
	return rec
}

// ListTokenNodes returns the secret-tree nodes attached to a token (for display
// and for pre-checking the edit form).
func (d *DB) ListTokenNodes(tokenID string) ([]TokenNode, error) {
	rows, err := d.q.ListTokenNodes(context.Background(), tokenID)
	if err != nil {
		return nil, fmt.Errorf("list token nodes: %w", err)
	}
	out := make([]TokenNode, len(rows))
	for i, r := range rows {
		out[i] = TokenNode{ID: r.ID, Kind: r.Kind, Name: r.Name}
	}
	return out, nil
}

// AuthorizedSecretsForToken resolves every leaf secret a token may read — its
// directly-attached nodes plus the subtree beneath any attached group — and
// decrypts each value. Returns a map keyed by the globally-unique secret name.
func (d *DB) AuthorizedSecretsForToken(ctx context.Context, tokenID string) (map[string]string, error) {
	rows, err := d.q.AuthorizedSecretsForToken(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("query authorized secrets for token: %w", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		plain, err := d.DecryptValue(r.Value)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret %s: %w", r.ID, err)
		}
		out[r.Name] = plain
	}
	return out, nil
}

// TouchMachineToken records that a token was just used (best-effort: callers
// log and ignore failures, since a missed timestamp must not block a vend).
func (d *DB) TouchMachineToken(id string) error {
	return d.q.TouchMachineToken(context.Background(), sqlcdb.TouchMachineTokenParams{
		LastUsedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		ID:         id,
	})
}

// ListMachineTokens returns all tokens (without the secret value, which is not
// stored) for the admin UI/API. Attached nodes are loaded separately via
// ListTokenNodes by callers that need them.
func (d *DB) ListMachineTokens() ([]MachineToken, error) {
	rows, err := d.q.ListMachineTokens(context.Background())
	if err != nil {
		return nil, fmt.Errorf("query machine tokens: %w", err)
	}
	tokens := make([]MachineToken, len(rows))
	for i, r := range rows {
		tokens[i] = *machineTokenFromRow(r.ID, r.Name, r.TokenPrefix, r.CreatedAt, r.LastUsedAt)
	}
	return tokens, nil
}

// DeleteMachineToken revokes a token by ID. Its node attachments are removed by
// ON DELETE CASCADE.
func (d *DB) DeleteMachineToken(id string) error {
	result, err := d.q.DeleteMachineToken(context.Background(), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountMachineTokens returns the total number of machine tokens.
func (d *DB) CountMachineTokens() (int, error) {
	count, err := d.q.CountMachineTokens(context.Background())
	return int(count), err
}
