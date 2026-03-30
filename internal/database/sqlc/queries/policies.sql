-- name: CreatePolicy :exec
INSERT INTO access_policies (id, name, repository_pattern, ref_pattern, environment_id, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetPolicy :one
SELECT p.id, p.name, p.repository_pattern, p.ref_pattern, p.environment_id, e.project, e.environment, p.created_at
FROM access_policies p
JOIN environments e ON e.id = p.environment_id
WHERE p.id = ?;

-- name: ListPolicies :many
SELECT p.id, p.name, p.repository_pattern, p.ref_pattern, p.environment_id, e.project, e.environment, p.created_at
FROM access_policies p
JOIN environments e ON e.id = p.environment_id
ORDER BY p.name;

-- name: UpdatePolicy :execresult
UPDATE access_policies SET name = ?, repository_pattern = ?, ref_pattern = ?, environment_id = ?
WHERE id = ?;

-- name: DeletePolicy :execresult
DELETE FROM access_policies WHERE id = ?;

-- name: CountPolicies :one
SELECT COUNT(*) FROM access_policies;
