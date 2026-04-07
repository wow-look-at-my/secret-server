package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
)

type Policy struct {
	ID                 string
	Name               string
	RepositoryPatterns []string
	RefPatterns        []string
	ActorPatterns      []string
	EnvironmentID      string
	Project            string // derived via JOIN with environments
	Environment        string // derived via JOIN with environments
	CreatedAt          time.Time
}

// encodePatterns serializes a pattern list for storage. A nil slice is
// stored as an empty JSON array so it round-trips cleanly.
func encodePatterns(patterns []string) (string, error) {
	if patterns == nil {
		patterns = []string{}
	}
	b, err := json.Marshal(patterns)
	if err != nil {
		return "", fmt.Errorf("marshal patterns: %w", err)
	}
	return string(b), nil
}

// decodePatterns deserializes a JSON-array column into a slice. Invalid
// or empty JSON yields a nil slice, which MatchingPolicies treats as
// "match any value" (preserving the legacy single-pattern "*" default).
func decodePatterns(s string) []string {
	var out []string
	if s == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		slog.Warn("invalid patterns JSON in access policy", "raw", s, "error", err)
		return nil
	}
	return out
}

func (d *DB) CreatePolicy(name string, repoPatterns, refPatterns, actorPatterns []string, environmentID string) (*Policy, error) {
	repoJSON, err := encodePatterns(repoPatterns)
	if err != nil {
		return nil, err
	}
	refJSON, err := encodePatterns(refPatterns)
	if err != nil {
		return nil, err
	}
	actorJSON, err := encodePatterns(actorPatterns)
	if err != nil {
		return nil, err
	}

	id := uuid.New().String()
	now := time.Now().UTC()
	err = d.q.CreatePolicy(context.Background(), sqlcdb.CreatePolicyParams{
		ID:                 id,
		Name:               name,
		RepositoryPatterns: repoJSON,
		RefPatterns:        refJSON,
		ActorPatterns:      actorJSON,
		EnvironmentID:      environmentID,
		CreatedAt:          now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert policy: %w", err)
	}
	return &Policy{
		ID:                 id,
		Name:               name,
		RepositoryPatterns: repoPatterns,
		RefPatterns:        refPatterns,
		ActorPatterns:      actorPatterns,
		EnvironmentID:      environmentID,
		CreatedAt:          now,
	}, nil
}

func (d *DB) GetPolicy(id string) (*Policy, error) {
	row, err := d.q.GetPolicy(context.Background(), id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query policy: %w", err)
	}
	return &Policy{
		ID:                 row.ID,
		Name:               row.Name,
		RepositoryPatterns: decodePatterns(row.RepositoryPatterns),
		RefPatterns:        decodePatterns(row.RefPatterns),
		ActorPatterns:      decodePatterns(row.ActorPatterns),
		EnvironmentID:      row.EnvironmentID,
		Project:            row.Project,
		Environment:        row.Environment,
		CreatedAt:          row.CreatedAt,
	}, nil
}

func (d *DB) ListPolicies() ([]Policy, error) {
	rows, err := d.q.ListPolicies(context.Background())
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	policies := make([]Policy, len(rows))
	for i, r := range rows {
		policies[i] = Policy{
			ID:                 r.ID,
			Name:               r.Name,
			RepositoryPatterns: decodePatterns(r.RepositoryPatterns),
			RefPatterns:        decodePatterns(r.RefPatterns),
			ActorPatterns:      decodePatterns(r.ActorPatterns),
			EnvironmentID:      r.EnvironmentID,
			Project:            r.Project,
			Environment:        r.Environment,
			CreatedAt:          r.CreatedAt,
		}
	}
	return policies, nil
}

func (d *DB) UpdatePolicy(id, name string, repoPatterns, refPatterns, actorPatterns []string, environmentID string) error {
	repoJSON, err := encodePatterns(repoPatterns)
	if err != nil {
		return err
	}
	refJSON, err := encodePatterns(refPatterns)
	if err != nil {
		return err
	}
	actorJSON, err := encodePatterns(actorPatterns)
	if err != nil {
		return err
	}

	result, err := d.q.UpdatePolicy(context.Background(), sqlcdb.UpdatePolicyParams{
		Name:               name,
		RepositoryPatterns: repoJSON,
		RefPatterns:        refJSON,
		ActorPatterns:      actorJSON,
		EnvironmentID:      environmentID,
		ID:                 id,
	})
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

func (d *DB) DeletePolicy(id string) error {
	result, err := d.q.DeletePolicy(context.Background(), id)
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

// MatchingPolicies returns policies that match the given repository, ref,
// and actor. A policy matches when the value matches any of its listed
// patterns for each field (AND across fields, OR within a field). An
// empty list for a field acts as a wildcard.
func (d *DB) MatchingPolicies(repository, ref, actor string) ([]Policy, error) {
	policies, err := d.ListPolicies()
	if err != nil {
		return nil, err
	}

	var matched []Policy
	for _, p := range policies {
		repoMatch, err := anyMatch(p.RepositoryPatterns, repository)
		if err != nil {
			slog.Warn("invalid repository glob pattern in policy", "policy_id", p.ID, "patterns", p.RepositoryPatterns, "error", err)
			continue
		}
		refMatch, err := anyMatch(p.RefPatterns, ref)
		if err != nil {
			slog.Warn("invalid ref glob pattern in policy", "policy_id", p.ID, "patterns", p.RefPatterns, "error", err)
			continue
		}
		actorMatch, err := anyMatch(p.ActorPatterns, actor)
		if err != nil {
			slog.Warn("invalid actor glob pattern in policy", "policy_id", p.ID, "patterns", p.ActorPatterns, "error", err)
			continue
		}
		if repoMatch && refMatch && actorMatch {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

// anyMatch returns true when value matches any of the given glob patterns.
// An empty pattern list acts as a wildcard (returns true).
func anyMatch(patterns []string, value string) (bool, error) {
	if len(patterns) == 0 {
		return true, nil
	}
	for _, p := range patterns {
		ok, err := matchGlob(p, value)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
