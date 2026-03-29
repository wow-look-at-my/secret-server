-- name: CreatePolicy :exec
INSERT INTO access_policies (id, name, repository_pattern, ref_pattern, project, environment, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetPolicy :one
SELECT id, name, repository_pattern, ref_pattern, project, environment, created_at
FROM access_policies WHERE id = ?;

-- name: ListPolicies :many
SELECT id, name, repository_pattern, ref_pattern, project, environment, created_at
FROM access_policies ORDER BY name;

-- name: UpdatePolicy :execresult
UPDATE access_policies SET name = ?, repository_pattern = ?, ref_pattern = ?, project = ?, environment = ?
WHERE id = ?;

-- name: DeletePolicy :execresult
DELETE FROM access_policies WHERE id = ?;

-- name: CountPolicies :one
SELECT COUNT(*) FROM access_policies;
