package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchingPolicyIDsMergeQueueRef guards the requirement that a plain
// `refs/heads/*` ref pattern authorizes GitHub merge-queue refs, which have the
// deeply nested shape `refs/heads/gh-readonly-queue/<base>/pr-<N>-<sha>`.
// SQLite GLOB's `*` matches across `/` boundaries — a property we rely on for
// this to work without users inventing a special merge-queue pattern.
func TestMatchingPolicyIDsMergeQueueRef(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	p, err := db.CreatePolicy("branches", []string{"myorg/*"}, []string{"refs/heads/*"}, []string{"*"})
	require.Nil(t, err)

	mergeQueueRef := "refs/heads/gh-readonly-queue/main/pr-151-f601177f87aafb2fec9add87471ca3854e9200c4"
	ids, err := db.MatchingPolicyIDs(ctx, "myorg/repo", mergeQueueRef, "github-merge-queue[bot]")
	require.Nil(t, err)
	assert.Equal(t, []string{p.ID}, ids)
}
