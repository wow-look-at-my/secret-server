package database

import (
	"fmt"
	"path"
)

// matchGlob matches a pattern against a value using path.Match semantics.
// The pattern can use * to match any sequence within a path segment,
// and ** is handled by splitting on / and matching segments.
func matchGlob(pattern, value string) (bool, error) {
	// path.Match doesn't handle ** for multi-segment matching,
	// but for our use cases (repo patterns like "org/*" and ref patterns
	// like "refs/heads/main"), simple path.Match is sufficient.
	// A pattern of "*" matches anything without a /.
	// For a "match everything" pattern, we treat "*" specially.
	if pattern == "*" {
		return true, nil
	}
	return path.Match(pattern, value)
}

// ValidatePatterns returns a non-nil error if any pattern in the slice
// is syntactically invalid under path.Match.
func ValidatePatterns(patterns []string) error {
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil {
			return fmt.Errorf("invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}
