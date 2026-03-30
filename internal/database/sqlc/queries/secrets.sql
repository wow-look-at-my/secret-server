-- name: GetSecret :one
SELECT s.id, s.key, s.value, s.environment_id, e.project, e.environment, s.created_at, s.updated_at
FROM secrets s
JOIN environments e ON e.id = s.environment_id
WHERE s.id = ?;

-- name: CreateSecret :exec
INSERT INTO secrets (id, key, value, environment_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: UpdateSecret :execresult
UPDATE secrets SET key = ?, value = ?, environment_id = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteSecret :execresult
DELETE FROM secrets WHERE id = ?;

-- name: ListSecretsAll :many
SELECT s.id, s.key, s.environment_id, e.project, e.environment, s.created_at, s.updated_at
FROM secrets s
JOIN environments e ON e.id = s.environment_id
ORDER BY e.project, e.environment, s.key;

-- name: ListSecretsByProject :many
SELECT s.id, s.key, s.environment_id, e.project, e.environment, s.created_at, s.updated_at
FROM secrets s
JOIN environments e ON e.id = s.environment_id
WHERE e.project = ?
ORDER BY e.project, e.environment, s.key;

-- name: ListSecretsByEnv :many
SELECT s.id, s.key, s.environment_id, e.project, e.environment, s.created_at, s.updated_at
FROM secrets s
JOIN environments e ON e.id = s.environment_id
WHERE e.environment = ?
ORDER BY e.project, e.environment, s.key;

-- name: ListSecretsByProjectAndEnv :many
SELECT s.id, s.key, s.environment_id, e.project, e.environment, s.created_at, s.updated_at
FROM secrets s
JOIN environments e ON e.id = s.environment_id
WHERE e.project = ? AND e.environment = ?
ORDER BY e.project, e.environment, s.key;

-- name: GetSecretsByEnvironmentID :many
SELECT key, value FROM secrets WHERE environment_id = ?;

-- name: CountSecrets :one
SELECT COUNT(*) FROM secrets;

-- name: SecretCountsByProjectEnv :many
SELECT e.project, e.environment, COUNT(*) AS secret_count
FROM secrets s
JOIN environments e ON e.id = s.environment_id
GROUP BY e.project, e.environment
ORDER BY e.project, e.environment;
