package database

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/wow-look-at-my/secret-server/internal/crypto"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when an update or delete affects zero rows.
var ErrNotFound = errors.New("not found")

type DB struct {
	db        *sql.DB
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
	d := &DB{db: db, encryptor: encryptor}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	// Environments table (must exist before FK-referencing tables).
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS environments (
			id TEXT PRIMARY KEY,
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(project, environment)
		);
	`)
	if err != nil {
		return fmt.Errorf("create environments table: %w", err)
	}

	// Check if we need to migrate from old schema (project/environment columns)
	// to new schema (environment_id FK).
	needsMigration, err := d.hasOldSchema()
	if err != nil {
		return fmt.Errorf("check schema: %w", err)
	}

	if needsMigration {
		if err := d.migrateToEnvironmentID(); err != nil {
			return fmt.Errorf("migrate to environment_id: %w", err)
		}
	} else {
		// Fresh install or already migrated — create tables with new schema.
		_, err = d.db.Exec(`
			CREATE TABLE IF NOT EXISTS secrets (
				id TEXT PRIMARY KEY,
				key TEXT NOT NULL,
				value BLOB NOT NULL,
				environment_id TEXT NOT NULL REFERENCES environments(id),
				created_at DATETIME NOT NULL DEFAULT (datetime('now')),
				updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
				UNIQUE(key, environment_id)
			);

			CREATE TABLE IF NOT EXISTS access_policies (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				repository_pattern TEXT NOT NULL,
				ref_pattern TEXT NOT NULL DEFAULT '*',
				environment_id TEXT NOT NULL REFERENCES environments(id),
				created_at DATETIME NOT NULL DEFAULT (datetime('now'))
			);

			CREATE INDEX IF NOT EXISTS idx_secrets_env_id ON secrets(environment_id);
			CREATE INDEX IF NOT EXISTS idx_policies_env_id ON access_policies(environment_id);
		`)
		if err != nil {
			return err
		}
	}

	return nil
}

// hasOldSchema returns true if the secrets table has a "project" column
// (old schema) rather than "environment_id" (new schema).
func (d *DB) hasOldSchema() (bool, error) {
	rows, err := d.db.Query("PRAGMA table_info(secrets)")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	hasProject := false
	hasAnyColumn := false
	for rows.Next() {
		hasAnyColumn = true
		var cid int
		var name, typ string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == "project" {
			hasProject = true
		}
	}
	if !hasAnyColumn {
		// Table doesn't exist yet — fresh install.
		return false, rows.Err()
	}
	return hasProject, rows.Err()
}

// migrateToEnvironmentID converts the old schema (project/environment columns)
// to the new schema (environment_id FK).
func (d *DB) migrateToEnvironmentID() error {
	// First, seed environments from existing data so every row has a match.
	if err := d.seedEnvironments(); err != nil {
		return fmt.Errorf("seed environments: %w", err)
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Must disable FK checks during table recreation to avoid issues
	// with dropping referenced tables.
	if _, err := tx.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}

	stmts := []string{
		`CREATE TABLE secrets_new (
			id TEXT PRIMARY KEY,
			key TEXT NOT NULL,
			value BLOB NOT NULL,
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(key, environment_id)
		)`,
		`INSERT INTO secrets_new (id, key, value, environment_id, created_at, updated_at)
			SELECT s.id, s.key, s.value, e.id, s.created_at, s.updated_at
			FROM secrets s
			JOIN environments e ON e.project = s.project AND e.environment = s.environment`,
		`DROP TABLE secrets`,
		`ALTER TABLE secrets_new RENAME TO secrets`,
		`CREATE INDEX idx_secrets_env_id ON secrets(environment_id)`,

		`CREATE TABLE access_policies_new (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			repository_pattern TEXT NOT NULL,
			ref_pattern TEXT NOT NULL DEFAULT '*',
			environment_id TEXT NOT NULL REFERENCES environments(id),
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`INSERT INTO access_policies_new (id, name, repository_pattern, ref_pattern, environment_id, created_at)
			SELECT p.id, p.name, p.repository_pattern, p.ref_pattern, e.id, p.created_at
			FROM access_policies p
			JOIN environments e ON e.project = p.project AND e.environment = p.environment`,
		`DROP TABLE access_policies`,
		`ALTER TABLE access_policies_new RENAME TO access_policies`,
		`CREATE INDEX idx_policies_env_id ON access_policies(environment_id)`,
	}

	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("exec %q: %w", stmt[:40], err)
		}
	}

	if _, err := tx.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return err
	}

	return tx.Commit()
}

func (d *DB) seedEnvironments() error {
	rows, err := d.db.Query(`
		SELECT DISTINCT project, environment FROM secrets
		UNION
		SELECT DISTINCT project, environment FROM access_policies
	`)
	if err != nil {
		return fmt.Errorf("query existing project/env pairs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var project, environment string
		if err := rows.Scan(&project, &environment); err != nil {
			return fmt.Errorf("scan project/env pair: %w", err)
		}
		_, err := d.db.Exec(
			"INSERT OR IGNORE INTO environments (id, project, environment) VALUES (?, ?, ?)",
			uuid.New().String(), project, environment,
		)
		if err != nil {
			return fmt.Errorf("seed environment %s/%s: %w", project, environment, err)
		}
	}
	return rows.Err()
}
