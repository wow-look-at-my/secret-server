-- name: CreateMachineToken :exec
INSERT INTO machine_tokens (id, name, token_hash, token_prefix, policy_id, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMachineTokenByHash :one
SELECT t.id, t.name, t.token_prefix, t.policy_id, p.name AS policy_name, t.created_at, t.last_used_at
FROM machine_tokens t
LEFT JOIN access_policies p ON p.id = t.policy_id
WHERE t.token_hash = ?;

-- name: GetMachineToken :one
SELECT t.id, t.name, t.token_prefix, t.policy_id, p.name AS policy_name, t.created_at, t.last_used_at
FROM machine_tokens t
LEFT JOIN access_policies p ON p.id = t.policy_id
WHERE t.id = ?;

-- name: ListMachineTokens :many
SELECT t.id, t.name, t.token_prefix, t.policy_id, p.name AS policy_name, t.created_at, t.last_used_at
FROM machine_tokens t
LEFT JOIN access_policies p ON p.id = t.policy_id
ORDER BY t.created_at DESC;

-- name: SetMachineTokenPolicy :exec
UPDATE machine_tokens SET policy_id = ? WHERE id = ?;

-- name: DeleteMachineToken :execresult
DELETE FROM machine_tokens WHERE id = ?;

-- name: TouchMachineToken :exec
UPDATE machine_tokens SET last_used_at = ? WHERE id = ?;

-- name: CountMachineTokens :one
SELECT COUNT(*) FROM machine_tokens;

-- name: AttachNodeToToken :exec
INSERT OR IGNORE INTO machine_token_nodes (token_id, node_id) VALUES (?, ?);

-- name: DeleteTokenNodes :exec
DELETE FROM machine_token_nodes WHERE token_id = ?;

-- name: ListTokenNodes :many
SELECT sn.id, sn.kind, sn.name
FROM machine_token_nodes mtn
JOIN secret_nodes sn ON sn.id = mtn.node_id
WHERE mtn.token_id = ?
ORDER BY sn.kind DESC, sn.name;
