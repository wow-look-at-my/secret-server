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

-- Machine tokens: a bearer credential for clients that can't present a GitHub
-- OIDC token (e.g. webhook-runner hooks). A token grants secrets two ways,
-- either or both: by attaching directly to secret-tree nodes
-- (machine_token_nodes) and/or via the optional bound policy (nullable
-- policy_id, ON DELETE SET NULL — deleting a policy unbinds it but keeps the
-- token). Only the SHA-256 hash is stored; the plaintext (sst_<random>) is shown
-- once at creation.
CREATE TABLE IF NOT EXISTS machine_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL DEFAULT '',
    policy_id    TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
    can_attest_github_pushes INTEGER NOT NULL DEFAULT 0
        CHECK (can_attest_github_pushes IN (0, 1)),
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    last_used_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_machine_tokens_policy ON machine_tokens(policy_id);

-- The secret-tree nodes a machine token may read. Attaching a group grants its
-- whole subtree, resolved by the same recursive CTE the OIDC path uses
-- (AuthorizedSecretsForToken). ON DELETE CASCADE on both sides: dropping a token
-- or a node removes the attachment.
CREATE TABLE IF NOT EXISTS machine_token_nodes (
    token_id TEXT NOT NULL REFERENCES machine_tokens(id) ON DELETE CASCADE,
    node_id  TEXT NOT NULL REFERENCES secret_nodes(id)   ON DELETE CASCADE,
    PRIMARY KEY (token_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_machine_token_nodes_node ON machine_token_nodes(node_id);

-- Human provenance for Git smart-HTTP pushes brokered by Agent Host. GitHub
-- Actions joins the signed repository/ref/SHA claims in its OIDC token to this
-- table instead of assuming a GitHub App workflow actor is the human pusher.
CREATE TABLE IF NOT EXISTS github_push_provenance (
    repository       TEXT NOT NULL COLLATE NOCASE,
    ref              TEXT NOT NULL,
    sha              TEXT NOT NULL COLLATE NOCASE,
    github_user_id   TEXT NOT NULL,
    github_login     TEXT NOT NULL,
    machine_token_id TEXT NOT NULL,
    attested_at      DATETIME NOT NULL,
    PRIMARY KEY (repository, ref, sha)
);

CREATE INDEX IF NOT EXISTS idx_github_push_provenance_user
    ON github_push_provenance(github_user_id);
