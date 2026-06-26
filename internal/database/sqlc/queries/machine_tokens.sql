-- name: CreateMachineToken :exec
INSERT INTO machine_tokens (id, name, token_hash, token_prefix, environment_id, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMachineTokenByHash :one
SELECT t.id, t.name, t.token_prefix, t.environment_id, e.project, e.environment, t.created_at, t.last_used_at
FROM machine_tokens t
JOIN environments e ON e.id = t.environment_id
WHERE t.token_hash = ?;

-- name: ListMachineTokens :many
SELECT t.id, t.name, t.token_prefix, t.environment_id, e.project, e.environment, t.created_at, t.last_used_at
FROM machine_tokens t
JOIN environments e ON e.id = t.environment_id
ORDER BY t.created_at DESC;

-- name: DeleteMachineToken :execresult
DELETE FROM machine_tokens WHERE id = ?;

-- name: TouchMachineToken :exec
UPDATE machine_tokens SET last_used_at = ? WHERE id = ?;

-- name: CountMachineTokens :one
SELECT COUNT(*) FROM machine_tokens;
