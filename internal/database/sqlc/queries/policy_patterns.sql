-- name: InsertPolicyPattern :exec
INSERT INTO policy_patterns (policy_id, kind, pattern) VALUES (?, ?, ?);

-- name: DeleteAllPolicyPatterns :exec
DELETE FROM policy_patterns WHERE policy_id = ?;

-- name: DeletePolicyPatternsOfKind :exec
DELETE FROM policy_patterns WHERE policy_id = ? AND kind = ?;

-- name: ListPolicyPatterns :many
SELECT policy_id, kind, pattern
FROM policy_patterns
WHERE policy_id = ?
ORDER BY kind, pattern;

-- MatchingPolicyIDs lives in internal/database/policies.go (hand-rolled raw
-- SQL). sqlc v1.28.0 miscounts characters when SQLite `?` placeholders appear
-- in certain contexts, truncating the tail of the generated query string, so
-- this specific hot-path query is written directly instead of going through
-- sqlc codegen.
