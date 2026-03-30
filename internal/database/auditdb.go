package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"

	_ "modernc.org/sqlite"
)

// AuditDB is a separate SQLite database for audit log entries.
// It is isolated from the main secrets database to prevent corruption
// of credential data during hardware/power failures.
type AuditDB struct {
	db *sql.DB
	q  *sqlcdb.Queries
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
	a := &AuditDB{db: db, q: sqlcdb.New(db)}
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
	return a.q.CreateAuditEntry(context.Background(), sqlcdb.CreateAuditEntryParams{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Action:       action,
		ActorType:    actorType,
		ActorID:      actorID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
}

func (a *AuditDB) ListEntries(limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := a.q.ListAuditEntries(context.Background(), sqlcdb.ListAuditEntriesParams{
		Limit:  int64(limit),
		Offset: int64(offset),
	})
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	entries := make([]AuditEntry, len(rows))
	for i, r := range rows {
		entries[i] = AuditEntry{
			ID:           r.ID,
			Timestamp:    r.Timestamp,
			Action:       r.Action,
			ActorType:    r.ActorType,
			ActorID:      r.ActorID,
			ResourceType: r.ResourceType,
			ResourceID:   r.ResourceID,
			Details:      r.Details,
		}
	}
	return entries, nil
}

func (a *AuditDB) CountEntries() (int, error) {
	count, err := a.q.CountAuditEntries(context.Background())
	return int(count), err
}
