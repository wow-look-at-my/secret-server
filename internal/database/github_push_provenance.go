package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// GitHubPushProvenance binds one successfully updated GitHub ref to the human
// OAuth identity that Agent Host resolved in its control plane.
type GitHubPushProvenance struct {
	Repository     string
	Ref            string
	SHA            string
	GitHubUserID   string
	GitHubLogin    string
	MachineTokenID string
	AttestedAt     time.Time
}

// SetMachineTokenGitHubAttestation explicitly grants or revokes the authority
// to write GitHub push provenance. Secret-reading authority alone is never
// sufficient to assert a human identity.
func (d *DB) SetMachineTokenGitHubAttestation(
	ctx context.Context,
	id string,
	enabled bool,
) error {
	value := 0
	if enabled {
		value = 1
	}
	result, err := d.db.ExecContext(
		ctx,
		`UPDATE machine_tokens
		 SET can_attest_github_pushes = ?
		 WHERE id = ?`,
		value,
		id,
	)
	if err != nil {
		return fmt.Errorf("set machine token GitHub attestation permission: %w", err)
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

// StoreGitHubPushProvenance upserts the identity for the exact ref state. A
// later push of the same SHA to the same ref intentionally replaces the older
// pusher because it is the event that can trigger the current workflow run.
func (d *DB) StoreGitHubPushProvenance(
	ctx context.Context,
	value GitHubPushProvenance,
) error {
	value.Repository = strings.ToLower(strings.TrimSpace(value.Repository))
	value.Ref = strings.TrimSpace(value.Ref)
	value.SHA = strings.ToLower(strings.TrimSpace(value.SHA))
	value.GitHubUserID = strings.TrimSpace(value.GitHubUserID)
	value.GitHubLogin = strings.TrimSpace(value.GitHubLogin)
	value.MachineTokenID = strings.TrimSpace(value.MachineTokenID)
	if value.AttestedAt.IsZero() {
		value.AttestedAt = time.Now().UTC()
	}
	if value.Repository == "" || value.Ref == "" || value.SHA == "" ||
		value.GitHubUserID == "" || value.GitHubLogin == "" ||
		value.MachineTokenID == "" {
		return errors.New("GitHub push provenance is incomplete")
	}
	if _, err := strconv.ParseInt(value.GitHubUserID, 10, 64); err != nil {
		return fmt.Errorf("invalid GitHub user ID: %w", err)
	}

	_, err := d.db.ExecContext(
		ctx,
		`INSERT INTO github_push_provenance (
			repository, ref, sha, github_user_id, github_login,
			machine_token_id, attested_at
		 ) VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(repository, ref, sha) DO UPDATE SET
			github_user_id = excluded.github_user_id,
			github_login = excluded.github_login,
			machine_token_id = excluded.machine_token_id,
			attested_at = excluded.attested_at`,
		value.Repository,
		value.Ref,
		value.SHA,
		value.GitHubUserID,
		value.GitHubLogin,
		value.MachineTokenID,
		value.AttestedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("store GitHub push provenance: %w", err)
	}
	return nil
}

// FindGitHubPushProvenance returns the exact attested pusher or nil when this
// workflow ref/SHA was not pushed through Agent Host.
func (d *DB) FindGitHubPushProvenance(
	ctx context.Context,
	repository, ref, sha string,
) (*GitHubPushProvenance, error) {
	row := d.db.QueryRowContext(
		ctx,
		`SELECT repository, ref, sha, github_user_id, github_login,
		        machine_token_id, attested_at
		 FROM github_push_provenance
		 WHERE repository = ? COLLATE NOCASE
		   AND ref = ?
		   AND sha = ? COLLATE NOCASE`,
		strings.TrimSpace(repository),
		strings.TrimSpace(ref),
		strings.TrimSpace(sha),
	)
	var value GitHubPushProvenance
	if err := row.Scan(
		&value.Repository,
		&value.Ref,
		&value.SHA,
		&value.GitHubUserID,
		&value.GitHubLogin,
		&value.MachineTokenID,
		&value.AttestedAt,
	); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("find GitHub push provenance: %w", err)
	}
	return &value, nil
}
