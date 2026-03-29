CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    value BLOB NOT NULL,
    project TEXT NOT NULL,
    environment TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(key, project, environment)
);

CREATE TABLE IF NOT EXISTS access_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    repository_pattern TEXT NOT NULL,
    ref_pattern TEXT NOT NULL DEFAULT '*',
    project TEXT NOT NULL,
    environment TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS environments (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    environment TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project, environment)
);

CREATE INDEX IF NOT EXISTS idx_secrets_project_env ON secrets(project, environment);
CREATE INDEX IF NOT EXISTS idx_policies_project_env ON access_policies(project, environment);
