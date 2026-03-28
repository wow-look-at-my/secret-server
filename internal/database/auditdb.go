package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	_ "modernc.org/sqlite"
)

// AuditDB is a separate SQLite database for audit log entries.
// It is isolated from the main secrets database to prevent corruption
// of credential data during hardware/power failures.
type AuditDB struct {
	db *sql.DB
}

type AuditEntry struct {
	ID           string
	Timestamp    time.Time
	Action       string
	ActorType    string
	ActorID      string
	ResourceType string
	ResourceID   string
	Details      string
}

func NewAuditDB(dbPath string) (*AuditDB, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open audit database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping audit database: %w", err)
	}
	a := &AuditDB{db: db}
	if err := a.migrate(); err != nil {
		return nil, fmt.Errorf("migrate audit database: %w", err)
	}
	return a, nil
}

func (a *AuditDB) Close() error {
	return a.db.Close()
}

func (a *AuditDB) migrate() error {
	_, err := a.db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
			action TEXT NOT NULL,
			actor_type TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL DEFAULT '',
			details TEXT NOT NULL DEFAULT '{}'
		);

		CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
	`)
	return err
}

func (a *AuditDB) CreateEntry(action, actorType, actorID, resourceType, resourceID, details string) error {
	id := uuid.New().String()
	_, err := a.db.Exec(
		"INSERT INTO audit_log (id, timestamp, action, actor_type, actor_id, resource_type, resource_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id, time.Now().UTC(), action, actorType, actorID, resourceType, resourceID, details,
	)
	return err
}

func (a *AuditDB) ListEntries(limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := a.db.Query(
		"SELECT id, timestamp, action, actor_type, actor_id, resource_type, resource_id, details FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &e.ActorType, &e.ActorID, &e.ResourceType, &e.ResourceID, &e.Details); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (a *AuditDB) CountEntries() (int, error) {
	var count int
	err := a.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count)
	return count, err
}
