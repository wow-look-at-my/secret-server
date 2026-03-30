package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Policy struct {
	ID                string
	Name              string
	RepositoryPattern string
	RefPattern        string
	EnvironmentID     string
	Project           string // derived via JOIN with environments
	Environment       string // derived via JOIN with environments
	CreatedAt         time.Time
}

func (d *DB) CreatePolicy(name, repoPattern, refPattern, environmentID string) (*Policy, error) {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := d.db.Exec(
		"INSERT INTO access_policies (id, name, repository_pattern, ref_pattern, environment_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, name, repoPattern, refPattern, environmentID, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert policy: %w", err)
	}
	return &Policy{
		ID: id, Name: name, RepositoryPattern: repoPattern,
		RefPattern: refPattern, EnvironmentID: environmentID, CreatedAt: now,
	}, nil
}

func (d *DB) GetPolicy(id string) (*Policy, error) {
	var p Policy
	err := d.db.QueryRow(`
		SELECT p.id, p.name, p.repository_pattern, p.ref_pattern, p.environment_id, e.project, e.environment, p.created_at
		FROM access_policies p
		JOIN environments e ON e.id = p.environment_id
		WHERE p.id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.RepositoryPattern, &p.RefPattern, &p.EnvironmentID, &p.Project, &p.Environment, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query policy: %w", err)
	}
	return &p, nil
}

func (d *DB) ListPolicies() ([]Policy, error) {
	rows, err := d.db.Query(`
		SELECT p.id, p.name, p.repository_pattern, p.ref_pattern, p.environment_id, e.project, e.environment, p.created_at
		FROM access_policies p
		JOIN environments e ON e.id = p.environment_id
		ORDER BY p.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.RepositoryPattern, &p.RefPattern, &p.EnvironmentID, &p.Project, &p.Environment, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (d *DB) UpdatePolicy(id, name, repoPattern, refPattern, environmentID string) error {
	result, err := d.db.Exec(
		"UPDATE access_policies SET name = ?, repository_pattern = ?, ref_pattern = ?, environment_id = ? WHERE id = ?",
		name, repoPattern, refPattern, environmentID, id,
	)
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
	result, err := d.db.Exec("DELETE FROM access_policies WHERE id = ?", id)
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

// MatchingPolicies returns policies that match the given repository and ref using glob patterns.
func (d *DB) MatchingPolicies(repository, ref string) ([]Policy, error) {
	policies, err := d.ListPolicies()
	if err != nil {
		return nil, err
	}

	var matched []Policy
	for _, p := range policies {
		repoMatch, _ := matchGlob(p.RepositoryPattern, repository)
		refMatch, _ := matchGlob(p.RefPattern, ref)
		if repoMatch && refMatch {
			matched = append(matched, p)
		}
	}
	return matched, nil
}
