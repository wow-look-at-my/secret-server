package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Environment struct {
	ID          string
	Project     string
	Environment string
	CreatedAt   time.Time
}

func (d *DB) CreateEnvironment(project, environment string) (*Environment, error) {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := d.db.Exec(
		"INSERT INTO environments (id, project, environment, created_at) VALUES (?, ?, ?, ?)",
		id, project, environment, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert environment: %w", err)
	}
	return &Environment{ID: id, Project: project, Environment: environment, CreatedAt: now}, nil
}

func (d *DB) GetEnvironment(id string) (*Environment, error) {
	var e Environment
	err := d.db.QueryRow(
		"SELECT id, project, environment, created_at FROM environments WHERE id = ?", id,
	).Scan(&e.ID, &e.Project, &e.Environment, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query environment: %w", err)
	}
	return &e, nil
}

func (d *DB) ListEnvironments() ([]Environment, error) {
	rows, err := d.db.Query(
		"SELECT id, project, environment, created_at FROM environments ORDER BY project, environment",
	)
	if err != nil {
		return nil, fmt.Errorf("query environments: %w", err)
	}
	defer rows.Close()

	var envs []Environment
	for rows.Next() {
		var e Environment
		if err := rows.Scan(&e.ID, &e.Project, &e.Environment, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan environment: %w", err)
		}
		envs = append(envs, e)
	}
	return envs, rows.Err()
}

func (d *DB) UpdateEnvironment(id, project, environment string) error {
	result, err := d.db.Exec(
		"UPDATE environments SET project = ?, environment = ? WHERE id = ?",
		project, environment, id,
	)
	if err != nil {
		return fmt.Errorf("update environment: %w", err)
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

func (d *DB) DeleteEnvironment(id string) error {
	result, err := d.db.Exec("DELETE FROM environments WHERE id = ?", id)
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

// EnvironmentInUse checks whether any secrets or policies reference the given environment ID.
func (d *DB) EnvironmentInUse(id string) (bool, error) {
	var count int
	err := d.db.QueryRow(
		"SELECT COUNT(*) FROM secrets WHERE environment_id = ?", id,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	err = d.db.QueryRow(
		"SELECT COUNT(*) FROM access_policies WHERE environment_id = ?", id,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CountEnvironments returns the total number of environments.
func (d *DB) CountEnvironments() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM environments").Scan(&count)
	return count, err
}
