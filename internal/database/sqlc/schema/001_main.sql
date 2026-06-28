CREATE TABLE IF NOT EXISTS secret_nodes (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('secret', 'group')),
    parent_id   TEXT REFERENCES secret_nodes(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    value       BLOB,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    CHECK ((kind = 'secret' AND value IS NOT NULL)
        OR (kind = 'group'  AND value IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_secret_nodes_parent ON secret_nodes(parent_id);

-- Secret names are globally unique across the whole server. This is the
-- invariant that lets the public API response use {name: value} with no risk
-- of collision between leaves in different subtrees.
CREATE UNIQUE INDEX IF NOT EXISTS idx_secret_nodes_secret_name
    ON secret_nodes(name) WHERE kind = 'secret';

-- Group names are unique within their parent. NULL parent_ids are treated as
-- distinct by SQLite, which is what we want (multiple root groups allowed).
CREATE UNIQUE INDEX IF NOT EXISTS idx_secret_nodes_group_name
    ON secret_nodes(parent_id, name) WHERE kind = 'group';

CREATE TABLE IF NOT EXISTS access_policies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- One row per pattern. Normalized so (a) patterns can be added/removed
-- individually, and (b) the public API can do glob matching inside SQLite via
-- its native GLOB operator instead of pulling every row into Go.
CREATE TABLE IF NOT EXISTS policy_patterns (
    policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL CHECK (kind IN ('repository', 'ref', 'actor')),
    pattern   TEXT NOT NULL,
    PRIMARY KEY (policy_id, kind, pattern)
);

CREATE INDEX IF NOT EXISTS idx_policy_patterns_kind ON policy_patterns(kind);

-- Which policies are attached to which nodes. Unordered set membership.
CREATE TABLE IF NOT EXISTS secret_node_policies (
    node_id   TEXT NOT NULL REFERENCES secret_nodes(id)    ON DELETE CASCADE,
    policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (node_id, policy_id)
);

CREATE INDEX IF NOT EXISTS idx_secret_node_policies_policy ON secret_node_policies(policy_id);

-- Directed "A must be evaluated before B" edges, scoped per node.
-- "policy_id depends on depends_on_id" = depends_on_id is evaluated first.
-- Policies with no edges between them may be evaluated in any order.
-- The composite FKs force both endpoints to be policies actually attached to
-- the same node.
CREATE TABLE IF NOT EXISTS policy_precedence (
    node_id       TEXT NOT NULL,
    policy_id     TEXT NOT NULL,
    depends_on_id TEXT NOT NULL,
    PRIMARY KEY (node_id, policy_id, depends_on_id),
    FOREIGN KEY (node_id, policy_id)     REFERENCES secret_node_policies(node_id, policy_id) ON DELETE CASCADE,
    FOREIGN KEY (node_id, depends_on_id) REFERENCES secret_node_policies(node_id, policy_id) ON DELETE CASCADE,
    CHECK (policy_id != depends_on_id)
);

CREATE INDEX IF NOT EXISTS idx_policy_precedence_dep ON policy_precedence(node_id, depends_on_id);
