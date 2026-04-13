-- name: CreatePolicy :exec
INSERT INTO access_policies (id, name, mode, repository_patterns, ref_patterns, actor_patterns, github_environment, environment_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetPolicy :one
SELECT p.id, p.name, p.mode, p.repository_patterns, p.ref_patterns, p.actor_patterns, p.github_environment, p.environment_id, e.project, e.environment, p.created_at
FROM access_policies p
JOIN environments e ON e.id = p.environment_id
WHERE p.id = ?;

-- name: ListPolicies :many
SELECT p.id, p.name, p.mode, p.repository_patterns, p.ref_patterns, p.actor_patterns, p.github_environment, p.environment_id, e.project, e.environment, p.created_at
FROM access_policies p
JOIN environments e ON e.id = p.environment_id
ORDER BY p.name;

-- name: UpdatePolicy :execresult
UPDATE access_policies SET name = ?, mode = ?, repository_patterns = ?, ref_patterns = ?, actor_patterns = ?, github_environment = ?, environment_id = ?
WHERE id = ?;

-- name: DeletePolicy :execresult
DELETE FROM access_policies WHERE id = ?;

-- name: CountPolicies :one
SELECT COUNT(*) FROM access_policies;
