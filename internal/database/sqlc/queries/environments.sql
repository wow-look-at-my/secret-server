-- name: CreateEnvironment :exec
INSERT INTO environments (id, project, environment, created_at) VALUES (?, ?, ?, ?);

-- name: GetEnvironment :one
SELECT id, project, environment, created_at FROM environments WHERE id = ?;

-- name: ListEnvironments :many
SELECT id, project, environment, created_at FROM environments ORDER BY project, environment;

-- name: UpdateEnvironment :execresult
UPDATE environments SET project = ?, environment = ? WHERE id = ?;

-- name: DeleteEnvironment :execresult
DELETE FROM environments WHERE id = ?;

-- name: CountEnvironments :one
SELECT COUNT(*) FROM environments;

-- name: EnvironmentInUseSecrets :one
SELECT COUNT(*) FROM secrets WHERE environment_id = ?;

-- name: EnvironmentInUsePolicies :one
SELECT COUNT(*) FROM access_policies WHERE environment_id = ?;

-- name: InsertEnvironmentIgnore :exec
INSERT OR IGNORE INTO environments (id, project, environment) VALUES (?, ?, ?);
