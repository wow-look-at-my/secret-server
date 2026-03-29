package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
)

type Secret struct {
	ID          string
	Key         string
	Value       string // plaintext — only populated on read
	Project     string
	Environment string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (d *DB) encryptValue(plaintext string) ([]byte, error) {
	encrypted, err := d.encryptor.Encrypt([]byte(plaintext))
	if err != nil {
		return nil, fmt.Errorf("encrypt value: %w", err)
	}
	encB64 := base64.StdEncoding.EncodeToString(encrypted)
	return []byte(encB64), nil
}

func (d *DB) decryptValue(enc []byte) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		return "", fmt.Errorf("decode secret value: %w", err)
	}
	plaintext, err := d.encryptor.Decrypt(encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plaintext), nil
}

func (d *DB) CreateSecret(key, value, project, environment string) (*Secret, error) {
	if ok, err := d.EnvironmentExists(project, environment); err != nil {
		return nil, fmt.Errorf("validate environment: %w", err)
	} else if !ok {
		return nil, ErrInvalidEnvironment
	}
	id := uuid.New().String()
	enc, err := d.encryptValue(value)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	err = d.q.CreateSecret(context.Background(), sqlcdb.CreateSecretParams{
		ID:          id,
		Key:         key,
		Value:       enc,
		Project:     project,
		Environment: environment,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert secret: %w", err)
	}
	return &Secret{ID: id, Key: key, Project: project, Environment: environment, CreatedAt: now, UpdatedAt: now}, nil
}

func (d *DB) GetSecret(id string) (*Secret, error) {
	row, err := d.q.GetSecret(context.Background(), id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query secret: %w", err)
	}
	plaintext, err := d.decryptValue(row.Value)
	if err != nil {
		return nil, err
	}
	return &Secret{
		ID:          row.ID,
		Key:         row.Key,
		Value:       plaintext,
		Project:     row.Project,
		Environment: row.Environment,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

type SecretListItem struct {
	ID          string
	Key         string
	Project     string
	Environment string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (d *DB) ListSecrets(project, environment string) ([]SecretListItem, error) {
	ctx := context.Background()
	switch {
	case project != "" && environment != "":
		rows, err := d.q.ListSecretsByProjectAndEnv(ctx, sqlcdb.ListSecretsByProjectAndEnvParams{
			Project:     project,
			Environment: environment,
		})
		if err != nil {
			return nil, fmt.Errorf("query secrets: %w", err)
		}
		secrets := make([]SecretListItem, len(rows))
		for i, r := range rows {
			secrets[i] = SecretListItem{ID: r.ID, Key: r.Key, Project: r.Project, Environment: r.Environment, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		}
		return secrets, nil
	case project != "":
		rows, err := d.q.ListSecretsByProject(ctx, project)
		if err != nil {
			return nil, fmt.Errorf("query secrets: %w", err)
		}
		secrets := make([]SecretListItem, len(rows))
		for i, r := range rows {
			secrets[i] = SecretListItem{ID: r.ID, Key: r.Key, Project: r.Project, Environment: r.Environment, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		}
		return secrets, nil
	case environment != "":
		rows, err := d.q.ListSecretsByEnv(ctx, environment)
		if err != nil {
			return nil, fmt.Errorf("query secrets: %w", err)
		}
		secrets := make([]SecretListItem, len(rows))
		for i, r := range rows {
			secrets[i] = SecretListItem{ID: r.ID, Key: r.Key, Project: r.Project, Environment: r.Environment, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		}
		return secrets, nil
	default:
		rows, err := d.q.ListSecretsAll(ctx)
		if err != nil {
			return nil, fmt.Errorf("query secrets: %w", err)
		}
		secrets := make([]SecretListItem, len(rows))
		for i, r := range rows {
			secrets[i] = SecretListItem{ID: r.ID, Key: r.Key, Project: r.Project, Environment: r.Environment, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		}
		return secrets, nil
	}
}

func (d *DB) UpdateSecret(id, key, value, project, environment string) error {
	if ok, err := d.EnvironmentExists(project, environment); err != nil {
		return fmt.Errorf("validate environment: %w", err)
	} else if !ok {
		return ErrInvalidEnvironment
	}
	enc, err := d.encryptValue(value)
	if err != nil {
		return err
	}
	result, err := d.q.UpdateSecret(context.Background(), sqlcdb.UpdateSecretParams{
		Key:         key,
		Value:       enc,
		Project:     project,
		Environment: environment,
		UpdatedAt:   time.Now().UTC(),
		ID:          id,
	})
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
	result, err := d.q.DeleteSecret(context.Background(), id)
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

// GetSecretsByProjectEnv returns decrypted secrets for a given project+environment.
func (d *DB) GetSecretsByProjectEnv(project, environment string) (map[string]string, error) {
	rows, err := d.q.GetSecretsByProjectEnv(context.Background(), sqlcdb.GetSecretsByProjectEnvParams{
		Project:     project,
		Environment: environment,
	})
	if err != nil {
		return nil, fmt.Errorf("query secrets: %w", err)
	}
	result := make(map[string]string, len(rows))
	for _, r := range rows {
		plaintext, err := d.decryptValue(r.Value)
		if err != nil {
			return nil, err
		}
		result[r.Key] = plaintext
	}
	return result, nil
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
	ctx := context.Background()
	var stats DashboardStats

	secretCount, err := d.q.CountSecrets(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalSecrets = int(secretCount)

	policyCount, err := d.q.CountPolicies(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalPolicies = int(policyCount)

	envCount, err := d.q.CountEnvironments(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalEnvironments = int(envCount)

	rows, err := d.q.SecretCountsByProjectEnv(ctx)
	if err != nil {
		return nil, err
	}
	stats.Projects = make([]ProjectStats, len(rows))
	for i, r := range rows {
		stats.Projects[i] = ProjectStats{
			Project:     r.Project,
			Environment: r.Environment,
			SecretCount: int(r.SecretCount),
		}
	}
	return &stats, nil
}
