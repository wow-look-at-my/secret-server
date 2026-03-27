package config

import (
	"encoding/hex"
	"fmt"
	"os"
)

type Config struct {
	ListenAddr        string
	DatabasePath      string
	EncryptionKey     []byte
	CFAccessTeamDomain string
	CFAccessAudience  string
	OIDCAudience      string
	LogLevel          string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        envOrDefault("LISTEN_ADDR", ":8080"),
		DatabasePath:      envOrDefault("DATABASE_PATH", "./secrets.db"),
		CFAccessTeamDomain: os.Getenv("CF_ACCESS_TEAM_DOMAIN"),
		CFAccessAudience:  os.Getenv("CF_ACCESS_AUDIENCE"),
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

	if cfg.CFAccessTeamDomain == "" {
		return nil, fmt.Errorf("CF_ACCESS_TEAM_DOMAIN is required")
	}
	if cfg.CFAccessAudience == "" {
		return nil, fmt.Errorf("CF_ACCESS_AUDIENCE is required")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
