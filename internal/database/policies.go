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
	Project           string
	Environment       string
	CreatedAt         time.Time
}

func (d *DB) CreatePolicy(name, repoPattern, refPattern, project, environment string) (*Policy, error) {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := d.db.Exec(
		"INSERT INTO access_policies (id, name, repository_pattern, ref_pattern, project, environment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, name, repoPattern, refPattern, project, environment, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert policy: %w", err)
	}
	return &Policy{
		ID: id, Name: name, RepositoryPattern: repoPattern,
		RefPattern: refPattern, Project: project, Environment: environment, CreatedAt: now,
	}, nil
}

func (d *DB) GetPolicy(id string) (*Policy, error) {
	var p Policy
	err := d.db.QueryRow(
		"SELECT id, name, repository_pattern, ref_pattern, project, environment, created_at FROM access_policies WHERE id = ?", id,
	).Scan(&p.ID, &p.Name, &p.RepositoryPattern, &p.RefPattern, &p.Project, &p.Environment, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query policy: %w", err)
	}
	return &p, nil
}

func (d *DB) ListPolicies() ([]Policy, error) {
	rows, err := d.db.Query(
		"SELECT id, name, repository_pattern, ref_pattern, project, environment, created_at FROM access_policies ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.RepositoryPattern, &p.RefPattern, &p.Project, &p.Environment, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (d *DB) UpdatePolicy(id, name, repoPattern, refPattern, project, environment string) error {
	result, err := d.db.Exec(
		"UPDATE access_policies SET name = ?, repository_pattern = ?, ref_pattern = ?, project = ?, environment = ? WHERE id = ?",
		name, repoPattern, refPattern, project, environment, id,
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
