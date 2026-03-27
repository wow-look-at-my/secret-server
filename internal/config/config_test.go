package config

import (
	"encoding/hex"
	"os"
	"testing"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
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
		"ENCRYPTION_KEY":		hex.EncodeToString(key),
		"CF_ACCESS_TEAM_DOMAIN":	"myteam",
		"CF_ACCESS_AUDIENCE":		"aud123",
	})
}

func TestLoadValid(t *testing.T) {
	validEnv(t)
	cfg, err := Load()
	require.Nil(t, err)

	assert.Equal(t, ":8080", cfg.ListenAddr)

	assert.Equal(t, "./secrets.db", cfg.DatabasePath)

	assert.Equal(t, 32, len(cfg.EncryptionKey))

	assert.Equal(t, "myteam", cfg.CFAccessTeamDomain)

	assert.Equal(t, "aud123", cfg.CFAccessAudience)

}

func TestLoadCustomValues(t *testing.T) {
	validEnv(t)
	setEnv(t, map[string]string{
		"LISTEN_ADDR":		":9090",
		"DATABASE_PATH":	"/tmp/test.db",
		"OIDC_AUDIENCE":	"https://secrets.example.com",
		"LOG_LEVEL":		"debug",
	})
	cfg, err := Load()
	require.Nil(t, err)

	assert.Equal(t, ":9090", cfg.ListenAddr)

	assert.Equal(t, "/tmp/test.db", cfg.DatabasePath)

	assert.Equal(t, "https://secrets.example.com", cfg.OIDCAudience)

	assert.Equal(t, "debug", cfg.LogLevel)

}

func TestLoadMissingEncryptionKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":		"",
		"CF_ACCESS_TEAM_DOMAIN":	"team",
		"CF_ACCESS_AUDIENCE":		"aud",
	})
	os.Unsetenv("ENCRYPTION_KEY")
	_, err := Load()
	require.NotNil(t, err)

}

func TestLoadBadHexKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":		"not-hex",
		"CF_ACCESS_TEAM_DOMAIN":	"team",
		"CF_ACCESS_AUDIENCE":		"aud",
	})
	_, err := Load()
	require.NotNil(t, err)

}

func TestLoadWrongKeyLength(t *testing.T) {
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":		hex.EncodeToString(make([]byte, 16)),
		"CF_ACCESS_TEAM_DOMAIN":	"team",
		"CF_ACCESS_AUDIENCE":		"aud",
	})
	_, err := Load()
	require.NotNil(t, err)

}

func TestLoadMissingCFTeamDomain(t *testing.T) {
	key := make([]byte, 32)
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":		hex.EncodeToString(key),
		"CF_ACCESS_TEAM_DOMAIN":	"",
		"CF_ACCESS_AUDIENCE":		"aud",
	})
	os.Unsetenv("CF_ACCESS_TEAM_DOMAIN")
	_, err := Load()
	require.NotNil(t, err)

}

func TestLoadMissingCFAudience(t *testing.T) {
	key := make([]byte, 32)
	setEnv(t, map[string]string{
		"ENCRYPTION_KEY":		hex.EncodeToString(key),
		"CF_ACCESS_TEAM_DOMAIN":	"team",
		"CF_ACCESS_AUDIENCE":		"",
	})
	os.Unsetenv("CF_ACCESS_AUDIENCE")
	_, err := Load()
	require.NotNil(t, err)

}
