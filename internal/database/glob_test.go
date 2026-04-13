package database

import (
	"testing"
	"github.com/wow-look-at-my/testify/assert"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern	string
		value	string
		want	bool
	}{
		// bare wildcard
		{"*", "anything", true},
		{"*", "org/repo", true},

		// single-segment wildcards
		{"myorg/*", "myorg/repo", true},
		{"myorg/*", "other/repo", false},
		{"myorg/specific", "myorg/specific", true},
		{"myorg/specific", "myorg/other", false},
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/main", "refs/heads/dev", false},
		{"refs/heads/*", "refs/heads/main", true},
		{"*", "refs/heads/main", true},

		// single-segment wildcard does NOT cross / boundaries
		{"refs/heads/*", "refs/heads/gh-readonly-queue/v1/pr-151-abc", false},

		// doublestar — trailing **
		{"refs/heads/**", "refs/heads/main", true},
		{"refs/heads/**", "refs/heads/feature/foo", true},
		{"refs/heads/**", "refs/heads/gh-readonly-queue/v1/pr-151-abc", true},
		{"refs/heads/**", "refs/tags/v1.0", false},

		// doublestar — middle **
		{"refs/**/main", "refs/heads/main", true},
		{"refs/**/main", "refs/remotes/origin/main", true},
		{"refs/**/main", "refs/heads/dev", false},

		// doublestar — leading **
		{"**/main", "refs/heads/main", true},
		{"**/main", "main", true},

		// doublestar matches zero segments
		{"refs/**/*", "refs/main", true},

		// exact match still works
		{"refs/heads/gh-readonly-queue/**", "refs/heads/gh-readonly-queue/v1/pr-151-abc", true},
		{"refs/heads/gh-readonly-queue/**", "refs/heads/main", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.value, func(t *testing.T) {
			got, err := matchGlob(tt.pattern, tt.value)
			assert.Nil(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

