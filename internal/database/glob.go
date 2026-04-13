package database

import (
	"fmt"
	"path"
	"strings"
)

// matchGlob matches a pattern against a value using path.Match semantics.
// The pattern can use * to match any sequence within a single path segment,
// and ** to match zero or more complete path segments (crossing / boundaries).
// A bare "*" pattern matches everything (special case).
func matchGlob(pattern, value string) (bool, error) {
	if pattern == "*" {
		return true, nil
	}
	if !strings.Contains(pattern, "**") {
		return path.Match(pattern, value)
	}
	return matchDoublestar(strings.Split(pattern, "/"), strings.Split(value, "/"))
}

// matchDoublestar recursively matches pattern segments against value segments.
// A "**" segment matches zero or more value segments.
func matchDoublestar(pat, val []string) (bool, error) {
	for len(pat) > 0 {
		if pat[0] == "**" {
			pat = pat[1:]
			if len(pat) == 0 {
				return true, nil // trailing ** matches everything remaining
			}
			for i := 0; i <= len(val); i++ {
				ok, err := matchDoublestar(pat, val[i:])
				if err != nil {
					return false, err
				}
				if ok {
					return true, nil
				}
			}
			return false, nil
		}
		if len(val) == 0 {
			return false, nil
		}
		ok, err := path.Match(pat[0], val[0])
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		pat = pat[1:]
		val = val[1:]
	}
	return len(val) == 0, nil
}

// ValidatePatterns returns a non-nil error if any pattern in the slice
// is syntactically invalid.
func ValidatePatterns(patterns []string) error {
	for _, p := range patterns {
		for _, seg := range strings.Split(p, "/") {
			if seg == "**" {
				continue
			}
			if _, err := path.Match(seg, ""); err != nil {
				return fmt.Errorf("invalid glob pattern %q: %w", p, err)
			}
		}
	}
	return nil
}
