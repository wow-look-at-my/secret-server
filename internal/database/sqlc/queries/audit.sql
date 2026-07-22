-- name: CreateAuditEntry :exec
INSERT INTO audit_log (id, timestamp, action, actor_type, actor_id, resource_type, resource_id, details)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAuditEntries :many
SELECT id, timestamp, action, actor_type, actor_id, resource_type, resource_id, details
FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?;

-- name: CountAuditEntries :one
SELECT COUNT(*) FROM audit_log;
