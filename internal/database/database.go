package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/wow-look-at-my/secret-server/internal/crypto"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when an update or delete affects zero rows.
var ErrNotFound = errors.New("not found")

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

// migrate runs all database-schema migrations in order. It is safe to call
// on a fresh database (all CREATE TABLEs are IF NOT EXISTS) and safe to call
// on a database from any prior schema version — the legacy converter detects
// the old environments-based layout and rewrites it into the composite tree.
func (d *DB) migrate() error {
	// Detect whether we're upgrading from the legacy schema (has an
	// `environments` table with project/environment columns) or starting
	// fresh / already on the composite schema.
	legacy, err := d.hasLegacySchema()
	if err != nil {
		return fmt.Errorf("check schema: %w", err)
	}
	if legacy {
		if err := d.migrateLegacyToComposite(); err != nil {
			return fmt.Errorf("migrate legacy schema: %w", err)
		}
		return nil
	}

	// Fresh install or already on the composite schema — create tables with
	// the current schema (IF NOT EXISTS makes this idempotent).
	if err := d.createCompositeSchema(d.db); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// hasLegacySchema reports whether the database still has the old
// environments-based layout. We detect it by the presence of the
// `environments` table, which the composite schema does not create.
func (d *DB) hasLegacySchema() (bool, error) {
	var name string
	err := d.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='environments'`).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// createCompositeSchema creates all tables and indexes for the composite
// secret-tree schema. Mirrors internal/database/sqlc/schema/001_main.sql.
func (d *DB) createCompositeSchema(exec sqlExecer) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS secret_nodes (
			id          TEXT PRIMARY KEY,
			kind        TEXT NOT NULL CHECK (kind IN ('secret', 'group')),
			parent_id   TEXT REFERENCES secret_nodes(id) ON DELETE CASCADE,
			name        TEXT NOT NULL,
			value       BLOB,
			created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			CHECK ((kind = 'secret' AND value IS NOT NULL)
				OR (kind = 'group'  AND value IS NULL))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_secret_nodes_parent ON secret_nodes(parent_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_secret_nodes_secret_name
			ON secret_nodes(name) WHERE kind = 'secret'`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_secret_nodes_group_name
			ON secret_nodes(parent_id, name) WHERE kind = 'group'`,
		`CREATE TABLE IF NOT EXISTS access_policies (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS policy_patterns (
			policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
			kind      TEXT NOT NULL CHECK (kind IN ('repository', 'ref', 'actor')),
			pattern   TEXT NOT NULL,
			PRIMARY KEY (policy_id, kind, pattern)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_patterns_kind ON policy_patterns(kind)`,
		`CREATE TABLE IF NOT EXISTS secret_node_policies (
			node_id   TEXT NOT NULL REFERENCES secret_nodes(id)    ON DELETE CASCADE,
			policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
			PRIMARY KEY (node_id, policy_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_secret_node_policies_policy ON secret_node_policies(policy_id)`,
		`CREATE TABLE IF NOT EXISTS policy_precedence (
			node_id       TEXT NOT NULL,
			policy_id     TEXT NOT NULL,
			depends_on_id TEXT NOT NULL,
			PRIMARY KEY (node_id, policy_id, depends_on_id),
			FOREIGN KEY (node_id, policy_id)     REFERENCES secret_node_policies(node_id, policy_id) ON DELETE CASCADE,
			FOREIGN KEY (node_id, depends_on_id) REFERENCES secret_node_policies(node_id, policy_id) ON DELETE CASCADE,
			CHECK (policy_id != depends_on_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_precedence_dep ON policy_precedence(node_id, depends_on_id)`,
	}
	for _, s := range stmts {
		if _, err := exec.ExecContext(context.Background(), s); err != nil {
			return fmt.Errorf("exec schema stmt: %w", err)
		}
	}
	return nil
}

// sqlExecer is the minimal interface we need for running CREATE TABLE etc.
// against either a *sql.DB or *sql.Tx.
type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// legacySecret is the old `secrets`-table row shape joined with its
// environment's project/environment columns. Used during migration.
type legacySecret struct {
	id          string
	project     string
	environment string
	key         string
	value       []byte
}

// legacyPolicy is the old `access_policies`-table row shape with JSON
// pattern columns. Used during migration.
type legacyPolicy struct {
	id                 string
	name               string
	repositoryPatterns []string
	refPatterns        []string
	actorPatterns      []string
	createdAt          time.Time
}

// migrateLegacyToComposite rewrites the old environments/secrets/policies
// schema into the new composite secret-tree schema. It preserves every
// secret as a loose root-level leaf (name-prefixed with its old
// project/environment to satisfy the new globally-unique-secret-name
// constraint) and every policy with its patterns normalized into
// policy_patterns. Attachments are NOT carried over — the admin re-attaches
// policies to nodes after upgrade.
func (d *DB) migrateLegacyToComposite() error {
	ctx := context.Background()

	slog.Info("legacy schema detected — migrating to composite secret tree")

	// Read out the old rows before touching the schema.
	secrets, err := d.readLegacySecrets(ctx)
	if err != nil {
		return fmt.Errorf("read legacy secrets: %w", err)
	}
	policies, err := d.readLegacyPolicies(ctx)
	if err != nil {
		return fmt.Errorf("read legacy policies: %w", err)
	}

	// Foreign keys must be OFF while we drop the old tables and create new
	// ones, because the old tables reference each other.
	if _, err := d.db.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}
	defer d.db.ExecContext(ctx, "PRAGMA foreign_keys = ON")

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Drop the old tables.
	for _, s := range []string{
		"DROP TABLE IF EXISTS secrets",
		"DROP TABLE IF EXISTS access_policies",
		"DROP TABLE IF EXISTS environments",
	} {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("drop legacy table: %w", err)
		}
	}

	// Create the new composite schema inside the transaction.
	if err := d.createCompositeSchema(tx); err != nil {
		return err
	}

	// Insert preserved secrets as loose root-level leaves.
	now := time.Now().UTC()
	for _, s := range secrets {
		name := fmt.Sprintf("%s-%s-%s", s.project, s.environment, s.key)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO secret_nodes (id, kind, parent_id, name, value, created_at, updated_at)
			 VALUES (?, 'secret', NULL, ?, ?, ?, ?)`,
			s.id, name, s.value, now, now,
		); err != nil {
			return fmt.Errorf("insert migrated secret %s: %w", name, err)
		}
	}

	// Insert preserved policies and their normalized pattern rows.
	for _, p := range policies {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO access_policies (id, name, created_at) VALUES (?, ?, ?)`,
			p.id, p.name, p.createdAt,
		); err != nil {
			return fmt.Errorf("insert migrated policy %s: %w", p.name, err)
		}
		// Legacy empty arrays are NOT synthesized into '*' rows — the new
		// semantics treat zero patterns of a kind as "matches nothing", and
		// any policy that relied on the old "empty = wildcard" behavior will
		// be visibly broken until the admin adds explicit patterns.
		for _, pat := range p.repositoryPatterns {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO policy_patterns (policy_id, kind, pattern) VALUES (?, 'repository', ?)`,
				p.id, pat,
			); err != nil {
				return fmt.Errorf("insert migrated repository pattern: %w", err)
			}
		}
		for _, pat := range p.refPatterns {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO policy_patterns (policy_id, kind, pattern) VALUES (?, 'ref', ?)`,
				p.id, pat,
			); err != nil {
				return fmt.Errorf("insert migrated ref pattern: %w", err)
			}
		}
		for _, pat := range p.actorPatterns {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO policy_patterns (policy_id, kind, pattern) VALUES (?, 'actor', ?)`,
				p.id, pat,
			); err != nil {
				return fmt.Errorf("insert migrated actor pattern: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	slog.Info("legacy migration complete",
		"migrated_secrets", len(secrets),
		"migrated_policies", len(policies),
	)
	return nil
}

// readLegacySecrets reads every row of the old secrets table, joined with
// the environments table to recover the project/environment tuple.
//
// The old schema went through several iterations:
//   - earliest: secrets table had project/environment TEXT columns directly
//   - later: secrets had environment_id FK to environments, which had
//     project/environment TEXT columns
//
// We handle both shapes so an upgrade from any old version works.
func (d *DB) readLegacySecrets(ctx context.Context) ([]legacySecret, error) {
	hasEnvID, err := columnExists(ctx, d.db, "secrets", "environment_id")
	if err != nil {
		return nil, err
	}
	var query string
	if hasEnvID {
		query = `SELECT s.id, e.project, e.environment, s.key, s.value
			FROM secrets s
			JOIN environments e ON e.id = s.environment_id`
	} else {
		query = `SELECT id, project, environment, key, value FROM secrets`
	}
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []legacySecret
	for rows.Next() {
		var s legacySecret
		if err := rows.Scan(&s.id, &s.project, &s.environment, &s.key, &s.value); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// readLegacyPolicies reads every row of the old access_policies table and
// decodes its JSON pattern columns. Handles both the plural pattern columns
// (repository_patterns as JSON array) and the even older singular pattern
// columns (repository_pattern as a single string).
func (d *DB) readLegacyPolicies(ctx context.Context) ([]legacyPolicy, error) {
	hasPlural, err := columnExists(ctx, d.db, "access_policies", "repository_patterns")
	if err != nil {
		return nil, err
	}

	var query string
	if hasPlural {
		query = `SELECT id, name, repository_patterns, ref_patterns, actor_patterns, created_at
			FROM access_policies`
	} else {
		// Even older schema had singular columns.
		query = `SELECT id, name, repository_pattern, ref_pattern, actor_pattern, created_at
			FROM access_policies`
	}
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []legacyPolicy
	for rows.Next() {
		var (
			id, name                  string
			repoCol, refCol, actorCol string
			createdAt                 time.Time
		)
		if err := rows.Scan(&id, &name, &repoCol, &refCol, &actorCol, &createdAt); err != nil {
			return nil, err
		}
		lp := legacyPolicy{id: id, name: name, createdAt: createdAt}
		if hasPlural {
			lp.repositoryPatterns = decodeLegacyPatternList(repoCol)
			lp.refPatterns = decodeLegacyPatternList(refCol)
			lp.actorPatterns = decodeLegacyPatternList(actorCol)
		} else {
			if repoCol != "" {
				lp.repositoryPatterns = []string{repoCol}
			}
			if refCol != "" {
				lp.refPatterns = []string{refCol}
			}
			if actorCol != "" {
				lp.actorPatterns = []string{actorCol}
			}
		}
		out = append(out, lp)
	}
	return out, rows.Err()
}

// decodeLegacyPatternList decodes a legacy JSON-array column. An empty or
// invalid value yields a nil slice, which the migration preserves as-is
// (no wildcard synthesis — see migrateLegacyToComposite).
func decodeLegacyPatternList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		slog.Warn("invalid legacy patterns JSON during migration; treating as empty", "raw", s, "error", err)
		return nil
	}
	return out
}

// columnExists reports whether the given table has a column with the given
// name. Uses PRAGMA table_info and returns false (without error) if the
// table itself doesn't exist.
func columnExists(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid       int
			name, typ string
			notnull   int
			dflt      sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, rows.Err()
		}
	}
	return false, rows.Err()
}
