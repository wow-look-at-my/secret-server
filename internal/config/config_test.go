package config

import (
	"encoding/hex"
	"os"
	"testing"
)

func setEnv(t *testing.T, kvs map[string]string) {
	t.Helper()
	for k, v := range kvs {
		t.Setenv(k, v)
	}
}

func validEnv(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":       hex.EncodeToString(key),
		"CF_ACCESS_TEAM_DOMAIN": "myteam",
		"CF_ACCESS_AUDIENCE":   "aud123",
	})
}

func TestLoadValid(t *testing.T) {
	validEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}
	if cfg.DatabasePath != "./secrets.db" {
		t.Errorf("DatabasePath = %q, want %q", cfg.DatabasePath, "./secrets.db")
	}
	if len(cfg.EncryptionKey) != 32 {
		t.Errorf("EncryptionKey length = %d, want 32", len(cfg.EncryptionKey))
	}
	if cfg.CFAccessTeamDomain != "myteam" {
		t.Errorf("CFAccessTeamDomain = %q, want %q", cfg.CFAccessTeamDomain, "myteam")
	}
	if cfg.CFAccessAudience != "aud123" {
		t.Errorf("CFAccessAudience = %q, want %q", cfg.CFAccessAudience, "aud123")
	}
}

func TestLoadCustomValues(t *testing.T) {
	validEnv(t)
	setEnv(t, map[string]string{
		"LISTEN_ADDR":   ":9090",
		"DATABASE_PATH": "/tmp/test.db",
		"OIDC_AUDIENCE": "https://secrets.example.com",
		"LOG_LEVEL":     "debug",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9090")
	}
	if cfg.DatabasePath != "/tmp/test.db" {
		t.Errorf("DatabasePath = %q, want %q", cfg.DatabasePath, "/tmp/test.db")
	}
	if cfg.OIDCAudience != "https://secrets.example.com" {
		t.Errorf("OIDCAudience = %q", cfg.OIDCAudience)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestLoadMissingEncryptionKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":       "",
		"CF_ACCESS_TEAM_DOMAIN": "team",
		"CF_ACCESS_AUDIENCE":   "aud",
	})
	os.Unsetenv("ENCRYPTION_KEY")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing encryption key")
	}
}

func TestLoadBadHexKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":       "not-hex",
		"CF_ACCESS_TEAM_DOMAIN": "team",
		"CF_ACCESS_AUDIENCE":   "aud",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for bad hex key")
	}
}

func TestLoadWrongKeyLength(t *testing.T) {
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":       hex.EncodeToString(make([]byte, 16)),
		"CF_ACCESS_TEAM_DOMAIN": "team",
		"CF_ACCESS_AUDIENCE":   "aud",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestLoadMissingCFTeamDomain(t *testing.T) {
	key := make([]byte, 32)
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":       hex.EncodeToString(key),
		"CF_ACCESS_TEAM_DOMAIN": "",
		"CF_ACCESS_AUDIENCE":   "aud",
	})
	os.Unsetenv("CF_ACCESS_TEAM_DOMAIN")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing CF team domain")
	}
}

func TestLoadMissingCFAudience(t *testing.T) {
	key := make([]byte, 32)
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":       hex.EncodeToString(key),
		"CF_ACCESS_TEAM_DOMAIN": "team",
		"CF_ACCESS_AUDIENCE":   "",
	})
	os.Unsetenv("CF_ACCESS_AUDIENCE")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing CF audience")
	}
}
