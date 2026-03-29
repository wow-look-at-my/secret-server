package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/wow-look-at-my/secret-server/internal/crypto"
	"github.com/wow-look-at-my/secret-server/internal/database/sqlc"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when an update or delete affects zero rows.
var ErrNotFound = errors.New("not found")

// ErrInvalidEnvironment is returned when a secret or policy references a
// project/environment pair that has not been created on the Environments page.
var ErrInvalidEnvironment = errors.New("unknown project/environment: create it on the Environments page first")

type DB struct {
	db        *sql.DB
	q         *sqlcdb.Queries
	encryptor *crypto.Encryptor
}

func New(dbPath string, encryptor *crypto.Encryptor) (*DB, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	d := &DB{db: db, q: sqlcdb.New(db), encryptor: encryptor}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			key TEXT NOT NULL,
			value BLOB NOT NULL,
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(key, project, environment)
		);

		CREATE TABLE IF NOT EXISTS access_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			repository_pattern TEXT NOT NULL,
			ref_pattern TEXT NOT NULL DEFAULT '*',
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS environments (
			id TEXT PRIMARY KEY,
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(project, environment)
		);

		CREATE INDEX IF NOT EXISTS idx_secrets_project_env ON secrets(project, environment);
		CREATE INDEX IF NOT EXISTS idx_policies_project_env ON access_policies(project, environment);
	`)
	if err != nil {
		return err
	}

	// Seed environments from existing secrets and policies data.
	return d.seedEnvironments()
}

func (d *DB) seedEnvironments() error {
	ctx := context.Background()
	pairs, err := d.q.SeedEnvironmentPairs(ctx)
	if err != nil {
		return fmt.Errorf("query existing project/env pairs: %w", err)
	}
	for _, p := range pairs {
		err := d.q.InsertEnvironmentIgnore(ctx, sqlcdb.InsertEnvironmentIgnoreParams{
			ID:          uuid.New().String(),
			Project:     p.Project,
			Environment: p.Environment,
		})
		if err != nil {
			return fmt.Errorf("seed environment %s/%s: %w", p.Project, p.Environment, err)
		}
	}
	return nil
}
