package database

import (
	"fmt"
	"strings"
)

// ValidatePatterns returns a non-nil error if any pattern in the slice is
// syntactically invalid as a SQLite GLOB pattern. GLOB is forgiving: any
// sequence of characters is technically a valid pattern, but unterminated
// character classes (`[...`) are a write-time bug we can catch here.
//
// Glob-matching itself lives inside SQLite (used via the GLOB operator in
// internal/database/policies.go MatchingPolicyIDs) — there is no Go-side
// matcher to keep in sync.
func ValidatePatterns(patterns []string) error {
	for _, p := range patterns {
		if err := validateGlob(p); err != nil {
			return fmt.Errorf("invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}

func validateGlob(p string) error {
	// Walk the pattern looking for an unclosed `[...` character class.
	// Backslashes escape the following character inside a class.
	inClass := false
	i := 0
	for i < len(p) {
		c := p[i]
		switch {
		case !inClass && c == '[':
			inClass = true
			i++
			// First character after `[` may be `]` (literal).
			if i < len(p) && p[i] == ']' {
				i++
			}
		case inClass && c == ']':
			inClass = false
			i++
		case inClass && c == '\\' && i+1 < len(p):
			i += 2
		default:
			i++
		}
	}
	if inClass {
		return fmt.Errorf("unclosed character class")
	}
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("pattern is empty or whitespace-only")
	}
	return nil
}
