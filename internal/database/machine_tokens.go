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
// two ways, either or both: by attaching directly to secret-tree nodes (see
// machine_token_nodes) and/or via an optional bound policy (PolicyID).
type MachineToken struct {
	ID                    string
	Name                  string
	TokenPrefix           string  // first chars of the token, for display ("sst_ab12…")
	PolicyID              *string // optional bound policy; nil when the token grants only via direct attachments
	PolicyName            *string // name of the bound policy (nil if unbound)
	CanAttestGitHubPushes bool    // separate authority; secret access alone cannot assert human identity
	CreatedAt             time.Time
	LastUsedAt            *time.Time // nil if never used
}

// ptrToNullString maps an optional policy id to a nullable column value,
// treating both nil and "" as "no policy".
func ptrToNullString(s *string) sql.NullString {
	if s == nil || *s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// nullStringToPtr maps a nullable column value back to an optional string.
func nullStringToPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	s := ns.String
	return &s
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

// CreateMachineToken mints a token granting the given direct node attachments
// and/or an optional bound policy (policyID nil/"" = no policy), and stores only
// its hash. Creation, the policy binding, and the attachments happen in one
// transaction, so a token never half-exists. The returned plaintext token is the
// only time it is ever available — the caller must surface it and then discard
// it. An unknown node ID or policy ID fails the whole create with ErrNotFound.
func (d *DB) CreateMachineToken(name string, policyID *string, nodeIDs []string) (token string, rec *MachineToken, err error) {
	if err := d.ensurePolicyExists(policyID); err != nil {
		return "", nil, err
	}
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
		PolicyID:    ptrToNullString(policyID),
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
		PolicyID:    nullStringToPtr(ptrToNullString(policyID)),
		CreatedAt:   now,
	}, nil
}

// UpdateMachineToken replaces a token's bound policy and direct node attachments
// with exactly the given values, in one transaction. policyID nil/"" unbinds any
// policy. An unknown node or policy ID fails the whole update with ErrNotFound,
// leaving the prior grant untouched.
func (d *DB) UpdateMachineToken(id string, policyID *string, nodeIDs []string) error {
	return d.updateMachineToken(id, policyID, nodeIDs, nil)
}

// UpdateMachineTokenWithGitHubAttestation updates the ordinary secret grants
// and the high-trust push-attestation capability in the same transaction. Admin
// handlers use this form so a failed update cannot leave half of the requested
// authorization applied.
func (d *DB) UpdateMachineTokenWithGitHubAttestation(
	id string,
	policyID *string,
	nodeIDs []string,
	canAttest bool,
) error {
	return d.updateMachineToken(id, policyID, nodeIDs, &canAttest)
}

func (d *DB) updateMachineToken(
	id string,
	policyID *string,
	nodeIDs []string,
	canAttest *bool,
) error {
	if err := d.ensurePolicyExists(policyID); err != nil {
		return err
	}
	ctx := context.Background()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rolled back unless Commit succeeds
	q := d.q.WithTx(tx)

	if err := q.SetMachineTokenPolicy(ctx, sqlcdb.SetMachineTokenPolicyParams{
		PolicyID: ptrToNullString(policyID),
		ID:       id,
	}); err != nil {
		return fmt.Errorf("set token policy: %w", err)
	}
	if err := q.DeleteTokenNodes(ctx, id); err != nil {
		return fmt.Errorf("clear token nodes: %w", err)
	}
	if err := attachNodesTx(ctx, q, id, nodeIDs); err != nil {
		return err
	}
	if canAttest != nil {
		value := 0
		if *canAttest {
			value = 1
		}
		result, err := tx.ExecContext(
			ctx,
			`UPDATE machine_tokens
			 SET can_attest_github_pushes = ?
			 WHERE id = ?`,
			value,
			id,
		)
		if err != nil {
			return fmt.Errorf("set token GitHub attestation permission: %w", err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
	}
	return tx.Commit()
}

// RegenerateMachineToken mints a fresh token value for an existing token,
// replacing the stored hash and display prefix in place. The token's name,
// bound policy, and node attachments are untouched — only the credential
// changes, so the old plaintext stops working the moment this returns. Like
// creation, the returned plaintext is the only time the new value is ever
// available. An unknown id returns ErrNotFound.
func (d *DB) RegenerateMachineToken(ctx context.Context, id string) (string, error) {
	token, hash, prefix, err := generateMachineToken()
	if err != nil {
		return "", err
	}
	result, err := d.q.UpdateMachineTokenCredentials(ctx, sqlcdb.UpdateMachineTokenCredentialsParams{
		TokenHash:   hash,
		TokenPrefix: prefix,
		ID:          id,
	})
	if err != nil {
		return "", fmt.Errorf("update machine token credentials: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", ErrNotFound
	}
	return token, nil
}

// ensurePolicyExists returns ErrNotFound if a non-empty policy id is given but
// no such policy exists. A nil/"" id (no policy) always passes.
func (d *DB) ensurePolicyExists(policyID *string) error {
	if policyID == nil || *policyID == "" {
		return nil
	}
	pol, err := d.GetPolicy(*policyID)
	if err != nil {
		return err
	}
	if pol == nil {
		return fmt.Errorf("%w: policy %q", ErrNotFound, *policyID)
	}
	return nil
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
	rec := machineTokenFromRow(
		row.ID,
		row.Name,
		row.TokenPrefix,
		row.PolicyID,
		row.PolicyName,
		row.CreatedAt,
		row.LastUsedAt,
	)
	if err := d.loadMachineTokenGitHubAttestation(rec); err != nil {
		return nil, err
	}
	return rec, nil
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
	rec := machineTokenFromRow(
		row.ID,
		row.Name,
		row.TokenPrefix,
		row.PolicyID,
		row.PolicyName,
		row.CreatedAt,
		row.LastUsedAt,
	)
	if err := d.loadMachineTokenGitHubAttestation(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// machineTokenFromRow builds a MachineToken from the columns every token query
// returns, normalizing the nullable policy binding and last_used_at.
func machineTokenFromRow(id, name, prefix string, policyID, policyName sql.NullString, createdAt time.Time, lastUsed sql.NullTime) *MachineToken {
	rec := &MachineToken{
		ID:          id,
		Name:        name,
		TokenPrefix: prefix,
		PolicyID:    nullStringToPtr(policyID),
		PolicyName:  nullStringToPtr(policyName),
		CreatedAt:   createdAt,
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		rec.LastUsedAt = &t
	}
	return rec
}

func (d *DB) loadMachineTokenGitHubAttestation(rec *MachineToken) error {
	enabled, err := d.MachineTokenCanAttestGitHubPushes(context.Background(), rec.ID)
	if err != nil {
		return err
	}
	rec.CanAttestGitHubPushes = enabled
	return nil
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

// MachineTokenSeedNodeIDs returns the set of secret-tree node IDs that any
// machine token grants directly — the union of every token's direct
// attachments and the nodes attached to any token's bound policy. This mirrors
// the seed of AuthorizedSecretsForToken (without the per-token filter or the
// downward subtree expansion); callers expand inheritance through the tree the
// same way the effective-policy walk does. The returned map has the same shape
// collectAttachedNodeIDs produces, so the UI can treat it identically.
func (d *DB) MachineTokenSeedNodeIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := d.q.ListNodeIDsWithMachineToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("list node ids with machine token: %w", err)
	}
	out := make(map[string]bool, len(rows))
	for _, id := range rows {
		out[id] = true
	}
	return out, nil
}

// AuthorizedSecretsForToken resolves every leaf secret a token may read — the
// union of its directly-attached nodes and its optional bound policy's nodes,
// each expanded through any attached group's subtree — and decrypts each value.
// Returns a map keyed by the globally-unique secret name.
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
		rec := machineTokenFromRow(
			r.ID,
			r.Name,
			r.TokenPrefix,
			r.PolicyID,
			r.PolicyName,
			r.CreatedAt,
			r.LastUsedAt,
		)
		if err := d.loadMachineTokenGitHubAttestation(rec); err != nil {
			return nil, err
		}
		tokens[i] = *rec
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
