package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
)

// Policy is the Go-side view of an access policy plus its normalized pattern
// rows. Patterns are loaded separately from the base row via ListPolicyPatterns.
type Policy struct {
	ID                 string
	Name               string
	RepositoryPatterns []string
	RefPatterns        []string
	ActorPatterns      []string
	CreatedAt          time.Time
}

// PatternKind enumerates the three pattern categories stored in
// policy_patterns.kind.
type PatternKind string

const (
	PatternRepository PatternKind = "repository"
	PatternRef        PatternKind = "ref"
	PatternActor      PatternKind = "actor"
)

// CreatePolicy inserts a new policy and its pattern rows in one transaction.
// Empty pattern slices produce zero rows for that kind, which means "matches
// nothing" under the new semantics — no implicit wildcard.
func (d *DB) CreatePolicy(name string, repoPatterns, refPatterns, actorPatterns []string) (*Policy, error) {
	if name == "" {
		return nil, errors.New("name is required")
	}
	if err := ValidatePatterns(repoPatterns); err != nil {
		return nil, err
	}
	if err := ValidatePatterns(refPatterns); err != nil {
		return nil, err
	}
	if err := ValidatePatterns(actorPatterns); err != nil {
		return nil, err
	}

	ctx := context.Background()
	id := uuid.New().String()
	now := time.Now().UTC()

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	q := d.q.WithTx(tx)

	if err := q.CreatePolicy(ctx, sqlcdb.CreatePolicyParams{
		ID:        id,
		Name:      name,
		CreatedAt: now,
	}); err != nil {
		return nil, fmt.Errorf("insert policy: %w", err)
	}
	if err := insertPolicyPatterns(ctx, q, id, repoPatterns, refPatterns, actorPatterns); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Policy{
		ID:                 id,
		Name:               name,
		RepositoryPatterns: append([]string(nil), repoPatterns...),
		RefPatterns:        append([]string(nil), refPatterns...),
		ActorPatterns:      append([]string(nil), actorPatterns...),
		CreatedAt:          now,
	}, nil
}

// insertPolicyPatterns writes the three pattern lists for a policy.
func insertPolicyPatterns(ctx context.Context, q *sqlcdb.Queries, policyID string, repo, ref, actor []string) error {
	for _, p := range repo {
		if err := q.InsertPolicyPattern(ctx, sqlcdb.InsertPolicyPatternParams{
			PolicyID: policyID,
			Kind:     string(PatternRepository),
			Pattern:  p,
		}); err != nil {
			return fmt.Errorf("insert repository pattern: %w", err)
		}
	}
	for _, p := range ref {
		if err := q.InsertPolicyPattern(ctx, sqlcdb.InsertPolicyPatternParams{
			PolicyID: policyID,
			Kind:     string(PatternRef),
			Pattern:  p,
		}); err != nil {
			return fmt.Errorf("insert ref pattern: %w", err)
		}
	}
	for _, p := range actor {
		if err := q.InsertPolicyPattern(ctx, sqlcdb.InsertPolicyPatternParams{
			PolicyID: policyID,
			Kind:     string(PatternActor),
			Pattern:  p,
		}); err != nil {
			return fmt.Errorf("insert actor pattern: %w", err)
		}
	}
	return nil
}

// GetPolicy fetches a policy by ID and loads its pattern rows.
// Returns (nil, nil) if not found.
func (d *DB) GetPolicy(id string) (*Policy, error) {
	ctx := context.Background()
	row, err := d.q.GetPolicy(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query policy: %w", err)
	}
	return d.hydratePolicy(ctx, row)
}

// ListPolicies returns every policy with its patterns populated.
func (d *DB) ListPolicies() ([]Policy, error) {
	ctx := context.Background()
	rows, err := d.q.ListPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	out := make([]Policy, 0, len(rows))
	for _, r := range rows {
		p, err := d.hydratePolicy(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

// hydratePolicy loads the pattern rows for a base access_policies row.
func (d *DB) hydratePolicy(ctx context.Context, row sqlcdb.AccessPolicy) (*Policy, error) {
	patterns, err := d.q.ListPolicyPatterns(ctx, row.ID)
	if err != nil {
		return nil, fmt.Errorf("list policy patterns: %w", err)
	}
	p := &Policy{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt}
	for _, pp := range patterns {
		switch PatternKind(pp.Kind) {
		case PatternRepository:
			p.RepositoryPatterns = append(p.RepositoryPatterns, pp.Pattern)
		case PatternRef:
			p.RefPatterns = append(p.RefPatterns, pp.Pattern)
		case PatternActor:
			p.ActorPatterns = append(p.ActorPatterns, pp.Pattern)
		}
	}
	return p, nil
}

// UpdatePolicy replaces a policy's name and full pattern set in one tx.
// The old pattern rows are deleted and the new ones inserted.
func (d *DB) UpdatePolicy(id, name string, repoPatterns, refPatterns, actorPatterns []string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if err := ValidatePatterns(repoPatterns); err != nil {
		return err
	}
	if err := ValidatePatterns(refPatterns); err != nil {
		return err
	}
	if err := ValidatePatterns(actorPatterns); err != nil {
		return err
	}

	ctx := context.Background()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := d.q.WithTx(tx)

	res, err := q.UpdatePolicyName(ctx, sqlcdb.UpdatePolicyNameParams{Name: name, ID: id})
	if err != nil {
		return fmt.Errorf("update policy name: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}

	if err := q.DeleteAllPolicyPatterns(ctx, id); err != nil {
		return fmt.Errorf("delete old patterns: %w", err)
	}
	if err := insertPolicyPatterns(ctx, q, id, repoPatterns, refPatterns, actorPatterns); err != nil {
		return err
	}
	return tx.Commit()
}

// DeletePolicy removes a policy. FK cascade cleans up pattern rows,
// attachment rows, and precedence edges.
func (d *DB) DeletePolicy(id string) error {
	res, err := d.q.DeletePolicy(context.Background(), id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AttachPolicy adds a policy to a node's attached set. Idempotent at the
// SQL level because of the primary key — attaching the same policy twice
// returns a UNIQUE constraint error.
func (d *DB) AttachPolicy(nodeID, policyID string) error {
	return d.q.AttachNodePolicy(context.Background(), sqlcdb.AttachNodePolicyParams{
		NodeID:   nodeID,
		PolicyID: policyID,
	})
}

// DetachPolicy removes a policy from a node's attached set. FK cascade on
// policy_precedence cleans up any edges touching this (node, policy) pair.
func (d *DB) DetachPolicy(nodeID, policyID string) error {
	res, err := d.q.DetachNodePolicy(context.Background(), sqlcdb.DetachNodePolicyParams{
		NodeID:   nodeID,
		PolicyID: policyID,
	})
	if err != nil {
		return fmt.Errorf("detach policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListNodePolicies returns the policies attached to a node in topological
// order (policies with no outgoing dependencies first, ties broken by name).
// When no precedence edges exist for the node the order is just alphabetical
// by policy name.
func (d *DB) ListNodePolicies(nodeID string) ([]Policy, error) {
	ctx := context.Background()
	rows, err := d.q.ListNodePolicies(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("list node policies: %w", err)
	}
	edges, err := d.q.ListNodePolicyPrecedence(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("list node precedence: %w", err)
	}

	ordered, err := topoSortPolicies(rows, edges)
	if err != nil {
		return nil, err
	}

	out := make([]Policy, 0, len(ordered))
	for _, row := range ordered {
		p, err := d.hydratePolicy(ctx, row)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

// ListNodePolicyPrecedence returns the raw precedence edges for a node.
// Used by the admin UI to render the dependency set separately from the
// ordered list.
func (d *DB) ListNodePolicyPrecedence(nodeID string) ([]sqlcdb.PolicyPrecedence, error) {
	return d.q.ListNodePolicyPrecedence(context.Background(), nodeID)
}

// topoSortPolicies runs Kahn's algorithm over the attached policies with
// the given "A depends on B" edges (A must appear AFTER B). Ties among
// currently-ready policies are broken by policy name for stability. A
// cycle in the edge set (which the DB permits, since SQLite can't enforce
// it) returns an error.
func topoSortPolicies(policies []sqlcdb.AccessPolicy, edges []sqlcdb.PolicyPrecedence) ([]sqlcdb.AccessPolicy, error) {
	if len(policies) == 0 {
		return nil, nil
	}
	// Filter edges down to policies that are actually in the set. The
	// composite FK should already guarantee this, but guard against stale
	// rows just in case.
	included := make(map[string]bool, len(policies))
	for _, p := range policies {
		included[p.ID] = true
	}

	// indegree[id] = number of policies id depends on.
	indegree := make(map[string]int, len(policies))
	// dependents[id] = policies that depend on id (edges pointing FROM id).
	dependents := make(map[string][]string)
	for _, p := range policies {
		indegree[p.ID] = 0
	}
	for _, e := range edges {
		if !included[e.PolicyID] || !included[e.DependsOnID] {
			continue
		}
		indegree[e.PolicyID]++
		dependents[e.DependsOnID] = append(dependents[e.DependsOnID], e.PolicyID)
	}

	byID := make(map[string]sqlcdb.AccessPolicy, len(policies))
	for _, p := range policies {
		byID[p.ID] = p
	}

	// ready set: policies with indegree 0. Sorted by name for stability.
	var ready []sqlcdb.AccessPolicy
	for _, p := range policies {
		if indegree[p.ID] == 0 {
			ready = append(ready, p)
		}
	}
	sortPoliciesByName(ready)

	out := make([]sqlcdb.AccessPolicy, 0, len(policies))
	for len(ready) > 0 {
		next := ready[0]
		ready = ready[1:]
		out = append(out, next)

		// Release dependents and collect any that became ready.
		var newlyReady []sqlcdb.AccessPolicy
		for _, dep := range dependents[next.ID] {
			indegree[dep]--
			if indegree[dep] == 0 {
				newlyReady = append(newlyReady, byID[dep])
			}
		}
		if len(newlyReady) > 0 {
			sortPoliciesByName(newlyReady)
			ready = mergeSortedPolicies(ready, newlyReady)
		}
	}
	if len(out) != len(policies) {
		return nil, errors.New("policy precedence contains a cycle")
	}
	return out, nil
}

func sortPoliciesByName(policies []sqlcdb.AccessPolicy) {
	sort.SliceStable(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})
}

// mergeSortedPolicies merges two slices of policies both sorted by name,
// preserving stability.
func mergeSortedPolicies(a, b []sqlcdb.AccessPolicy) []sqlcdb.AccessPolicy {
	out := make([]sqlcdb.AccessPolicy, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i].Name <= b[j].Name {
			out = append(out, a[i])
			i++
		} else {
			out = append(out, b[j])
			j++
		}
	}
	out = append(out, a[i:]...)
	out = append(out, b[j:]...)
	return out
}

// AddPrecedence records that policyID must be evaluated AFTER dependsOnID
// for the given node. "A depends on B" is modelled as an edge B -> A in the
// evaluation graph. Inserting a new edge from dependsOnID to policyID would
// close a cycle iff, in the existing graph, policyID can already reach
// dependsOnID — so that's the DFS we run before touching the table.
func (d *DB) AddPrecedence(nodeID, policyID, dependsOnID string) error {
	if policyID == dependsOnID {
		return errors.New("a policy cannot depend on itself")
	}
	ctx := context.Background()
	edges, err := d.q.ListNodePolicyPrecedence(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("list precedence: %w", err)
	}
	if reachable(edges, policyID, dependsOnID) {
		return errors.New("adding this edge would create a precedence cycle")
	}
	return d.q.AddPolicyPrecedence(ctx, sqlcdb.AddPolicyPrecedenceParams{
		NodeID:      nodeID,
		PolicyID:    policyID,
		DependsOnID: dependsOnID,
	})
}

// reachable returns true if target is reachable from start by following
// dependency edges (policy_id depends on depends_on_id = edge from depends_on_id
// to policy_id). Used by AddPrecedence to detect prospective cycles.
func reachable(edges []sqlcdb.PolicyPrecedence, start, target string) bool {
	if start == target {
		return true
	}
	// Adjacency: depends_on_id -> list of policy_ids that depend on it.
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.DependsOnID] = append(adj[e.DependsOnID], e.PolicyID)
	}
	visited := map[string]bool{start: true}
	stack := []string{start}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, next := range adj[n] {
			if next == target {
				return true
			}
			if !visited[next] {
				visited[next] = true
				stack = append(stack, next)
			}
		}
	}
	return false
}

// RemovePrecedence deletes a single dependency edge.
func (d *DB) RemovePrecedence(nodeID, policyID, dependsOnID string) error {
	res, err := d.q.RemovePolicyPrecedence(context.Background(), sqlcdb.RemovePolicyPrecedenceParams{
		NodeID:      nodeID,
		PolicyID:    policyID,
		DependsOnID: dependsOnID,
	})
	if err != nil {
		return fmt.Errorf("remove precedence: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// matchingPolicyIDsSQL is the raw SQL for MatchingPolicyIDs. This query is
// hand-rolled instead of going through sqlc codegen because sqlc v1.28.0
// truncates the tail of generated query strings when SQLite `?` placeholders
// appear in certain contexts (the offset bookkeeping gets off-by-N). See the
// note in internal/database/sqlc/queries/policy_patterns.sql.
const matchingPolicyIDsSQL = `
SELECT DISTINCT p.id
FROM access_policies p
JOIN policy_patterns pr ON pr.policy_id = p.id AND pr.kind = 'repository'
JOIN policy_patterns pf ON pf.policy_id = p.id AND pf.kind = 'ref'
JOIN policy_patterns pa ON pa.policy_id = p.id AND pa.kind = 'actor'
WHERE ? GLOB pr.pattern AND ? GLOB pf.pattern AND ? GLOB pa.pattern
`

// MatchingPolicyIDs returns every policy whose pattern rows all match the
// given (repository, ref, actor) claim tuple. A policy with zero patterns of
// any kind matches nothing for that kind — the inner join yields no rows.
//
// This is the hot path on every public API request. The matching runs entirely
// inside SQLite via its native GLOB operator; no rows cross the SQL boundary
// other than the matching IDs.
func (d *DB) MatchingPolicyIDs(ctx context.Context, repository, ref, actor string) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, matchingPolicyIDsSQL, repository, ref, actor)
	if err != nil {
		return nil, fmt.Errorf("query matching policies: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AuthorizedSecrets resolves the given matching policy IDs to every leaf
// secret that those policies authorize (directly or inherited via ancestor
// groups), and decrypts each secret value. Returns a map keyed by the
// globally-unique secret name.
func (d *DB) AuthorizedSecrets(ctx context.Context, policyIDs []string) (map[string]string, error) {
	if len(policyIDs) == 0 {
		return map[string]string{}, nil
	}
	rows, err := d.q.AuthorizedSecrets(ctx, policyIDs)
	if err != nil {
		return nil, fmt.Errorf("query authorized secrets: %w", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		plain, err := d.DecryptValue(r.Value)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret %s: %w", r.ID, err)
		}
		out[r.Name] = plain
	}
	return out, nil
}

// CountNodesReferencingPolicy returns the number of nodes that have the
// given policy attached. Used by the UI's "attached to N nodes" column.
func (d *DB) CountNodesReferencingPolicy(policyID string) (int64, error) {
	return d.q.CountNodesReferencingPolicy(context.Background(), policyID)
}

// ListNodesReferencingPolicy returns the nodes that have the given policy
// attached. Used by the backward-view admin page.
func (d *DB) ListNodesReferencingPolicy(policyID string) ([]ISecretNode, error) {
	rows, err := d.q.ListNodesReferencingPolicy(context.Background(), policyID)
	if err != nil {
		return nil, fmt.Errorf("list nodes referencing policy: %w", err)
	}
	out := make([]ISecretNode, 0, len(rows))
	for _, r := range rows {
		n, err := nodeFromRow(r, d)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
