package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
)

type Policy struct {
	ID                string
	Name              string
	RepositoryPattern string
	RefPattern        string
	ActorPattern      string
	EnvironmentID     string
	Project           string // derived via JOIN with environments
	Environment       string // derived via JOIN with environments
	CreatedAt         time.Time
}

func (d *DB) CreatePolicy(name, repoPattern, refPattern, actorPattern, environmentID string) (*Policy, error) {
	id := uuid.New().String()
	now := time.Now().UTC()
	err := d.q.CreatePolicy(context.Background(), sqlcdb.CreatePolicyParams{
		ID:                id,
		Name:              name,
		RepositoryPattern: repoPattern,
		RefPattern:        refPattern,
		ActorPattern:      actorPattern,
		EnvironmentID:     environmentID,
		CreatedAt:         now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert policy: %w", err)
	}
	return &Policy{
		ID: id, Name: name, RepositoryPattern: repoPattern,
		RefPattern: refPattern, ActorPattern: actorPattern,
		EnvironmentID: environmentID, CreatedAt: now,
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
		ID:                row.ID,
		Name:              row.Name,
		RepositoryPattern: row.RepositoryPattern,
		RefPattern:        row.RefPattern,
		ActorPattern:      row.ActorPattern,
		EnvironmentID:     row.EnvironmentID,
		Project:           row.Project,
		Environment:       row.Environment,
		CreatedAt:         row.CreatedAt,
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
			ID:                r.ID,
			Name:              r.Name,
			RepositoryPattern: r.RepositoryPattern,
			RefPattern:        r.RefPattern,
			ActorPattern:      r.ActorPattern,
			EnvironmentID:     r.EnvironmentID,
			Project:           r.Project,
			Environment:       r.Environment,
			CreatedAt:         r.CreatedAt,
		}
	}
	return policies, nil
}

func (d *DB) UpdatePolicy(id, name, repoPattern, refPattern, actorPattern, environmentID string) error {
	result, err := d.q.UpdatePolicy(context.Background(), sqlcdb.UpdatePolicyParams{
		Name:              name,
		RepositoryPattern: repoPattern,
		RefPattern:        refPattern,
		ActorPattern:      actorPattern,
		EnvironmentID:     environmentID,
		ID:                id,
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

// MatchingPolicies returns policies that match the given repository, ref, and actor using glob patterns.
func (d *DB) MatchingPolicies(repository, ref, actor string) ([]Policy, error) {
	policies, err := d.ListPolicies()
	if err != nil {
		return nil, err
	}

	var matched []Policy
	for _, p := range policies {
		repoMatch, err := matchGlob(p.RepositoryPattern, repository)
		if err != nil {
			slog.Warn("invalid repository glob pattern in policy", "policy_id", p.ID, "pattern", p.RepositoryPattern, "error", err)
			continue
		}
		refMatch, err := matchGlob(p.RefPattern, ref)
		if err != nil {
			slog.Warn("invalid ref glob pattern in policy", "policy_id", p.ID, "pattern", p.RefPattern, "error", err)
			continue
		}
		actorMatch, err := matchGlob(p.ActorPattern, actor)
		if err != nil {
			slog.Warn("invalid actor glob pattern in policy", "policy_id", p.ID, "pattern", p.ActorPattern, "error", err)
			continue
		}
		if repoMatch && refMatch && actorMatch {
			matched = append(matched, p)
		}
	}
	return matched, nil
}
