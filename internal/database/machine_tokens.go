package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
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
// it is shown to the operator exactly once, at creation. A token is bound to
// one policy and vends exactly that policy's authorized secrets.
type MachineToken struct {
	ID          string
	Name        string
	TokenPrefix string // first chars of the token, for display ("sst_ab12…")
	PolicyID    string
	PolicyName  string // derived via JOIN with access_policies
	CreatedAt   time.Time
	LastUsedAt  *time.Time // nil if never used
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

// CreateMachineToken mints a token bound to the given policy and stores only
// its hash. The returned plaintext token is the only time it is ever available
// — the caller must surface it to the operator and then discard it.
func (d *DB) CreateMachineToken(name, policyID string) (token string, rec *MachineToken, err error) {
	token, hash, prefix, err := generateMachineToken()
	if err != nil {
		return "", nil, err
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	err = d.q.CreateMachineToken(context.Background(), sqlcdb.CreateMachineTokenParams{
		ID:          id,
		Name:        name,
		TokenHash:   hash,
		TokenPrefix: prefix,
		PolicyID:    policyID,
		CreatedAt:   now,
	})
	if err != nil {
		return "", nil, fmt.Errorf("insert machine token: %w", err)
	}
	return token, &MachineToken{
		ID:          id,
		Name:        name,
		TokenPrefix: prefix,
		PolicyID:    policyID,
		CreatedAt:   now,
	}, nil
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
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query machine token: %w", err)
	}
	rec := &MachineToken{
		ID:          row.ID,
		Name:        row.Name,
		TokenPrefix: row.TokenPrefix,
		PolicyID:    row.PolicyID,
		PolicyName:  row.PolicyName,
		CreatedAt:   row.CreatedAt,
	}
	if row.LastUsedAt.Valid {
		t := row.LastUsedAt.Time
		rec.LastUsedAt = &t
	}
	return rec, nil
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
// stored) for the admin UI/API.
func (d *DB) ListMachineTokens() ([]MachineToken, error) {
	rows, err := d.q.ListMachineTokens(context.Background())
	if err != nil {
		return nil, fmt.Errorf("query machine tokens: %w", err)
	}
	tokens := make([]MachineToken, len(rows))
	for i, r := range rows {
		t := MachineToken{
			ID:          r.ID,
			Name:        r.Name,
			TokenPrefix: r.TokenPrefix,
			PolicyID:    r.PolicyID,
			PolicyName:  r.PolicyName,
			CreatedAt:   r.CreatedAt,
		}
		if r.LastUsedAt.Valid {
			lu := r.LastUsedAt.Time
			t.LastUsedAt = &lu
		}
		tokens[i] = t
	}
	return tokens, nil
}

// DeleteMachineToken revokes a token by ID.
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
