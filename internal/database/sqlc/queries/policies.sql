-- name: CreatePolicy :exec
-- name: CreatePolicy :exec
INSERT INTO access_policies (id, name, mode, github_environment, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetPolicy :one
-- name: GetPolicy :one
SELECT id, name, mode, github_environment, created_at FROM access_policies WHERE id = ?;

-- name: ListPolicies :many
-- name: ListPolicies :many
SELECT id, name, mode, github_environment, created_at FROM access_policies ORDER BY name;

-- name: UpdatePolicyName :execresult
UPDATE access_policies SET name = ? WHERE id = ?;

-- name: UpdatePolicyMode :execresult
UPDATE access_policies SET name = ?, mode = ?, github_environment = ? WHERE id = ?;

-- name: DeletePolicy :execresult
DELETE FROM access_policies WHERE id = ?;

-- name: CountPolicies :one
SELECT COUNT(*) FROM access_policies;

-- name: AttachNodePolicy :exec
INSERT INTO secret_node_policies (node_id, policy_id) VALUES (?, ?);

-- name: DetachNodePolicy :execresult
DELETE FROM secret_node_policies WHERE node_id = ? AND policy_id = ?;

-- name: ListNodePolicies :many
SELECT p.id, p.name, p.created_at
FROM secret_node_policies snp
JOIN access_policies p ON p.id = snp.policy_id
WHERE snp.node_id = ?
ORDER BY p.name;

-- name: CountAttachedPoliciesForNode :one
SELECT COUNT(*) FROM secret_node_policies WHERE node_id = ?;

-- name: ListNodesReferencingPolicy :many
SELECT sn.id, sn.kind, sn.parent_id, sn.name, sn.value, sn.created_at, sn.updated_at
FROM secret_node_policies snp
JOIN secret_nodes sn ON sn.id = snp.node_id
WHERE snp.policy_id = ?
ORDER BY sn.name;

-- name: CountNodesReferencingPolicy :one
SELECT COUNT(*) FROM secret_node_policies WHERE policy_id = ?;

-- name: AddPolicyPrecedence :exec
INSERT INTO policy_precedence (node_id, policy_id, depends_on_id) VALUES (?, ?, ?);

-- name: RemovePolicyPrecedence :execresult
DELETE FROM policy_precedence
WHERE node_id = ? AND policy_id = ? AND depends_on_id = ?;

-- name: ListNodePolicyPrecedence :many
SELECT node_id, policy_id, depends_on_id
FROM policy_precedence
WHERE node_id = ?;
