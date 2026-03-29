package database

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Secret struct {
	ID            string
	Key           string
	Value         string // plaintext — only populated on read
	EnvironmentID string
	Project       string // derived via JOIN with environments
	Environment   string // derived via JOIN with environments
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (d *DB) CreateSecret(key, value, environmentID string) (*Secret, error) {
	id := uuid.New().String()
	encrypted, err := d.encryptor.Encrypt([]byte(value))
	if err != nil {
		return nil, fmt.Errorf("encrypt value: %w", err)
	}
	encB64 := base64.StdEncoding.EncodeToString(encrypted)
	now := time.Now().UTC()
	_, err = d.db.Exec(
		"INSERT INTO secrets (id, key, value, environment_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, key, encB64, environmentID, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert secret: %w", err)
	}
	return &Secret{ID: id, Key: key, EnvironmentID: environmentID, CreatedAt: now, UpdatedAt: now}, nil
}

func (d *DB) GetSecret(id string) (*Secret, error) {
	var s Secret
	var encB64 string
	err := d.db.QueryRow(`
		SELECT s.id, s.key, s.value, s.environment_id, e.project, e.environment, s.created_at, s.updated_at
		FROM secrets s
		JOIN environments e ON e.id = s.environment_id
		WHERE s.id = ?`, id,
	).Scan(&s.ID, &s.Key, &encB64, &s.EnvironmentID, &s.Project, &s.Environment, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query secret: %w", err)
	}
	encrypted, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, fmt.Errorf("decode secret value: %w", err)
	}
	plaintext, err := d.encryptor.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	s.Value = string(plaintext)
	return &s, nil
}

type SecretListItem struct {
	ID            string
	Key           string
	EnvironmentID string
	Project       string
	Environment   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (d *DB) ListSecrets(project, environment string) ([]SecretListItem, error) {
	query := `SELECT s.id, s.key, s.environment_id, e.project, e.environment, s.created_at, s.updated_at
		FROM secrets s
		JOIN environments e ON e.id = s.environment_id
		WHERE 1=1`
	var args []any
	if project != "" {
		query += " AND e.project = ?"
		args = append(args, project)
	}
	if environment != "" {
		query += " AND e.environment = ?"
		args = append(args, environment)
	}
	query += " ORDER BY e.project, e.environment, s.key"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query secrets: %w", err)
	}
	defer rows.Close()

	var secrets []SecretListItem
	for rows.Next() {
		var s SecretListItem
		if err := rows.Scan(&s.ID, &s.Key, &s.EnvironmentID, &s.Project, &s.Environment, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		secrets = append(secrets, s)
	}
	return secrets, rows.Err()
}

func (d *DB) UpdateSecret(id, key, value, environmentID string) error {
	encrypted, err := d.encryptor.Encrypt([]byte(value))
	if err != nil {
		return fmt.Errorf("encrypt value: %w", err)
	}
	encB64 := base64.StdEncoding.EncodeToString(encrypted)
	result, err := d.db.Exec(
		"UPDATE secrets SET key = ?, value = ?, environment_id = ?, updated_at = ? WHERE id = ?",
		key, encB64, environmentID, time.Now().UTC(), id,
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

func (d *DB) DeleteSecret(id string) error {
	result, err := d.db.Exec("DELETE FROM secrets WHERE id = ?", id)
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

// GetSecretsByEnvironmentID returns decrypted secrets for a given environment ID.
func (d *DB) GetSecretsByEnvironmentID(environmentID string) (map[string]string, error) {
	rows, err := d.db.Query(
		"SELECT key, value FROM secrets WHERE environment_id = ?",
		environmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("query secrets: %w", err)
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var key, encB64 string
		if err := rows.Scan(&key, &encB64); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		encrypted, err := base64.StdEncoding.DecodeString(encB64)
		if err != nil {
			return nil, fmt.Errorf("decode secret value: %w", err)
		}
		plaintext, err := d.encryptor.Decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret: %w", err)
		}
		result[key] = string(plaintext)
	}
	return result, rows.Err()
}

// DashboardStats returns counts for the dashboard.
type DashboardStats struct {
	TotalSecrets      int
	TotalPolicies     int
	TotalEnvironments int
	Projects          []ProjectStats
}

type ProjectStats struct {
	Project     string
	Environment string
	SecretCount int
}

func (d *DB) GetDashboardStats() (*DashboardStats, error) {
	var stats DashboardStats

	err := d.db.QueryRow("SELECT COUNT(*) FROM secrets").Scan(&stats.TotalSecrets)
	if err != nil {
		return nil, err
	}
	err = d.db.QueryRow("SELECT COUNT(*) FROM access_policies").Scan(&stats.TotalPolicies)
	if err != nil {
		return nil, err
	}
	err = d.db.QueryRow("SELECT COUNT(*) FROM environments").Scan(&stats.TotalEnvironments)
	if err != nil {
		return nil, err
	}

	rows, err := d.db.Query(`
		SELECT e.project, e.environment, COUNT(*)
		FROM secrets s
		JOIN environments e ON e.id = s.environment_id
		GROUP BY e.project, e.environment
		ORDER BY e.project, e.environment`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ps ProjectStats
		if err := rows.Scan(&ps.Project, &ps.Environment, &ps.SecretCount); err != nil {
			return nil, err
		}
		stats.Projects = append(stats.Projects, ps)
	}
	return &stats, rows.Err()
}
