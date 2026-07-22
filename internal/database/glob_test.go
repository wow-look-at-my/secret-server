package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePatternsGood(t *testing.T) {
	// All of these are syntactically valid GLOB patterns that ValidatePatterns
	// should accept.
	cases := [][]string{
		{"*"},
		{"org/*"},
		{"refs/heads/main"},
		{"refs/tags/v*"},
		{"[abc]"},
		{"a[!b]c"},
	}
	for _, c := range cases {
		assert.Nil(t, ValidatePatterns(c))
	}
	// Nil slice is trivially valid.
	assert.Nil(t, ValidatePatterns(nil))
}

func TestValidatePatternsBad(t *testing.T) {
	// Unclosed character class.
	assert.NotNil(t, ValidatePatterns([]string{"org/["}))
	// Empty pattern is rejected — a blank line is almost certainly a typo.
	assert.NotNil(t, ValidatePatterns([]string{""}))
	assert.NotNil(t, ValidatePatterns([]string{"  "}))
}
