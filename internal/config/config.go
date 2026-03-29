package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

type Config struct {
	ListenAddr         string
	DatabasePath       string
	AuditDatabasePath  string
	EncryptionKey      []byte
	CSRFKey            []byte
	CFAccessTeamDomain    string
	CFAccessAdminAudience string
	OIDCAudience          string
	LogLevel              string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:         envOrDefault("LISTEN_ADDR", ":8080"),
		DatabasePath:       envOrDefault("DATABASE_PATH", "./secrets.db"),
		AuditDatabasePath:  envOrDefault("AUDIT_DATABASE_PATH", "./audit.db"),
		CFAccessTeamDomain: os.Getenv("CF_ACCESS_TEAM_DOMAIN"),
		CFAccessAdminAudience:  os.Getenv("CF_ACCESS_ADMIN_AUDIENCE"),
		OIDCAudience:      os.Getenv("OIDC_AUDIENCE"),
		LogLevel:          envOrDefault("LOG_LEVEL", "info"),
	}

	keyHex := os.Getenv("ENCRYPTION_KEY")
	if keyHex == "" {
		return nil, fmt.Errorf("ENCRYPTION_KEY is required")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be hex-encoded: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	cfg.EncryptionKey = key

	hkdfReader := hkdf.New(sha256.New, cfg.EncryptionKey, nil, []byte("csrf-auth-key"))
	csrfKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, csrfKey); err != nil {
		return nil, fmt.Errorf("failed to derive CSRF key: %w", err)
	}
	cfg.CSRFKey = csrfKey

	if cfg.CFAccessTeamDomain == "" {
		return nil, fmt.Errorf("CF_ACCESS_TEAM_DOMAIN is required")
	}
	if cfg.CFAccessAdminAudience == "" {
		return nil, fmt.Errorf("CF_ACCESS_ADMIN_AUDIENCE is required")
	}
	if cfg.OIDCAudience == "" {
		return nil, fmt.Errorf("OIDC_AUDIENCE is required")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
