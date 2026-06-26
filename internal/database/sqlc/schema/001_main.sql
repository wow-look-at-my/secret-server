CREATE TABLE IF NOT EXISTS environments (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    environment TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project, environment)
);

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
    repository_patterns TEXT NOT NULL DEFAULT '[]',
    ref_patterns TEXT NOT NULL DEFAULT '["*"]',
    actor_patterns TEXT NOT NULL DEFAULT '["*"]',
    environment_id TEXT NOT NULL REFERENCES environments(id),
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Machine tokens: non-Actions clients (e.g. webhook-runner hooks) that can't
-- present a GitHub OIDC token. Each token is a bearer credential bound to one
-- environment; only its SHA-256 hash is stored. Presenting the token to
-- GET /github/v1/secrets vends that environment's secrets.
CREATE TABLE IF NOT EXISTS machine_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL DEFAULT '',
    environment_id TEXT NOT NULL REFERENCES environments(id),
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    last_used_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_secrets_env_id ON secrets(environment_id);
CREATE INDEX IF NOT EXISTS idx_policies_env_id ON access_policies(environment_id);
CREATE INDEX IF NOT EXISTS idx_machine_tokens_env_id ON machine_tokens(environment_id);
