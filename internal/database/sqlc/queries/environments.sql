-- name: CreateEnvironment :exec
INSERT INTO environments (id, project, environment, created_at) VALUES (?, ?, ?, ?);

-- name: GetEnvironment :one
SELECT id, project, environment, created_at FROM environments WHERE id = ?;

-- name: ListEnvironments :many
SELECT id, project, environment, created_at FROM environments ORDER BY project, environment;

-- name: DeleteEnvironment :execresult
DELETE FROM environments WHERE id = ?;

-- name: EnvironmentExists :one
SELECT COUNT(*) FROM environments WHERE project = ? AND environment = ?;

-- name: CountEnvironments :one
SELECT COUNT(*) FROM environments;

-- name: EnvironmentInUseSecrets :one
SELECT COUNT(*) FROM secrets WHERE project = ? AND environment = ?;

-- name: EnvironmentInUsePolicies :one
SELECT COUNT(*) FROM access_policies WHERE project = ? AND environment = ?;

-- name: SeedEnvironmentPairs :many
SELECT DISTINCT project, environment FROM secrets
UNION
SELECT DISTINCT project, environment FROM access_policies;

-- name: InsertEnvironmentIgnore :exec
INSERT OR IGNORE INTO environments (id, project, environment) VALUES (?, ?, ?);
