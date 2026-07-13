-- name: CreateSecretNode :exec
INSERT INTO secret_nodes (id, kind, parent_id, name, value, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSecretNode :one
SELECT id, kind, parent_id, name, value, created_at, updated_at
FROM secret_nodes
WHERE id = ?;

-- name: ListRootNodes :many
SELECT id, kind, parent_id, name, value, created_at, updated_at
FROM secret_nodes
WHERE parent_id IS NULL
ORDER BY kind DESC, name;

-- name: ListChildNodes :many
SELECT id, kind, parent_id, name, value, created_at, updated_at
FROM secret_nodes
WHERE parent_id = ?
ORDER BY kind DESC, name;

-- name: ListAllNodes :many
SELECT id, kind, parent_id, name, value, created_at, updated_at
FROM secret_nodes
ORDER BY kind DESC, name;

-- name: UpdateSecretNodeName :execresult
UPDATE secret_nodes SET name = ?, updated_at = ?
WHERE id = ?;

-- name: UpdateSecretNodeValue :execresult
UPDATE secret_nodes SET value = ?, updated_at = ?
WHERE id = ? AND kind = 'secret';

-- name: UpdateSecretNodeParent :execresult
UPDATE secret_nodes SET parent_id = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteSecretNode :execresult
DELETE FROM secret_nodes WHERE id = ?;

-- name: CountNodesByKind :one
SELECT COUNT(*) FROM secret_nodes WHERE kind = ?;

-- name: FindSecretByName :one
SELECT id, kind, parent_id, name, value, created_at, updated_at
FROM secret_nodes
WHERE name = ? AND kind = 'secret';

-- AuthorizedSecrets returns every leaf secret reachable from any of the given
-- policy IDs via a downward walk through attached nodes. A policy attached to
-- a group grants access to the whole subtree beneath it.
--
-- name: AuthorizedSecrets :many
WITH RECURSIVE authorized(id) AS (
    SELECT snp.node_id
    FROM secret_node_policies snp
    WHERE snp.policy_id IN (sqlc.slice('policy_ids'))
    UNION
    SELECT sn.id
    FROM secret_nodes sn
    JOIN authorized a ON sn.parent_id = a.id
)
SELECT sn.id, sn.name, sn.value
FROM secret_nodes sn
JOIN authorized a ON sn.id = a.id
WHERE sn.kind = 'secret';

-- AuthorizedSecretsForToken returns every leaf secret a machine token may read:
-- the union of its direct node attachments (machine_token_nodes) and the nodes
-- granted by its optional bound policy (secret_node_policies via policy_id),
-- each expanded down through any attached group's subtree. Same downward walk as
-- AuthorizedSecrets, just seeded from both sources; a token with no policy
-- contributes nothing from the policy branch.
--
-- name: AuthorizedSecretsForToken :many
WITH RECURSIVE authorized(id) AS (
    SELECT mtn.node_id
    FROM machine_token_nodes mtn
    WHERE mtn.token_id = sqlc.arg(token_id)
    UNION
    SELECT snp.node_id
    FROM secret_node_policies snp
    JOIN machine_tokens mt ON mt.policy_id = snp.policy_id
    WHERE mt.id = sqlc.arg(token_id)
    UNION
    SELECT sn.id
    FROM secret_nodes sn
    JOIN authorized a ON sn.parent_id = a.id
)
SELECT sn.id, sn.name, sn.value
FROM secret_nodes sn
JOIN authorized a ON sn.id = a.id
WHERE sn.kind = 'secret';
