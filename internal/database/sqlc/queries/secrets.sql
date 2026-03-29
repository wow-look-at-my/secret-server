-- name: GetSecret :one
SELECT id, key, value, project, environment, created_at, updated_at
FROM secrets WHERE id = ?;

-- name: CreateSecret :exec
INSERT INTO secrets (id, key, value, project, environment, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: UpdateSecret :execresult
UPDATE secrets SET key = ?, value = ?, project = ?, environment = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteSecret :execresult
DELETE FROM secrets WHERE id = ?;

-- name: ListSecretsAll :many
SELECT id, key, project, environment, created_at, updated_at
FROM secrets ORDER BY project, environment, key;

-- name: ListSecretsByProject :many
SELECT id, key, project, environment, created_at, updated_at
FROM secrets WHERE project = ? ORDER BY project, environment, key;

-- name: ListSecretsByEnv :many
SELECT id, key, project, environment, created_at, updated_at
FROM secrets WHERE environment = ? ORDER BY project, environment, key;

-- name: ListSecretsByProjectAndEnv :many
SELECT id, key, project, environment, created_at, updated_at
FROM secrets WHERE project = ? AND environment = ?
ORDER BY project, environment, key;

-- name: GetSecretsByProjectEnv :many
SELECT key, value FROM secrets WHERE project = ? AND environment = ?;

-- name: CountSecrets :one
SELECT COUNT(*) FROM secrets;

-- name: SecretCountsByProjectEnv :many
SELECT project, environment, COUNT(*) AS secret_count
FROM secrets GROUP BY project, environment ORDER BY project, environment;
