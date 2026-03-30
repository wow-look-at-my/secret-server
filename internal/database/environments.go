package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
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
	err := d.q.CreateEnvironment(context.Background(), sqlcdb.CreateEnvironmentParams{
		ID:          id,
		Project:     project,
		Environment: environment,
		CreatedAt:   now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert environment: %w", err)
	}
	return &Environment{ID: id, Project: project, Environment: environment, CreatedAt: now}, nil
}

func (d *DB) GetEnvironment(id string) (*Environment, error) {
	row, err := d.q.GetEnvironment(context.Background(), id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query environment: %w", err)
	}
	return &Environment{ID: row.ID, Project: row.Project, Environment: row.Environment, CreatedAt: row.CreatedAt}, nil
}

func (d *DB) ListEnvironments() ([]Environment, error) {
	rows, err := d.q.ListEnvironments(context.Background())
	if err != nil {
		return nil, fmt.Errorf("query environments: %w", err)
	}
	envs := make([]Environment, len(rows))
	for i, r := range rows {
		envs[i] = Environment{ID: r.ID, Project: r.Project, Environment: r.Environment, CreatedAt: r.CreatedAt}
	}
	return envs, nil
}

func (d *DB) UpdateEnvironment(id, project, environment string) error {
	result, err := d.q.UpdateEnvironment(context.Background(), sqlcdb.UpdateEnvironmentParams{
		Project:     project,
		Environment: environment,
		ID:          id,
	})
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
	result, err := d.q.DeleteEnvironment(context.Background(), id)
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
	ctx := context.Background()
	count, err := d.q.EnvironmentInUseSecrets(ctx, id)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	count, err = d.q.EnvironmentInUsePolicies(ctx, id)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CountEnvironments returns the total number of environments.
func (d *DB) CountEnvironments() (int, error) {
	count, err := d.q.CountEnvironments(context.Background())
	return int(count), err
}
