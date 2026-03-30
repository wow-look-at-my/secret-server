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
    repository_pattern TEXT NOT NULL,
    ref_pattern TEXT NOT NULL DEFAULT '*',
    environment_id TEXT NOT NULL REFERENCES environments(id),
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_secrets_env_id ON secrets(environment_id);
CREATE INDEX IF NOT EXISTS idx_policies_env_id ON access_policies(environment_id);
