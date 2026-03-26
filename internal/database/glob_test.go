package database

import "testing"

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"*", "org/repo", true},
		{"myorg/*", "myorg/repo", true},
		{"myorg/*", "other/repo", false},
		{"myorg/specific", "myorg/specific", true},
		{"myorg/specific", "myorg/other", false},
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/main", "refs/heads/dev", false},
		{"refs/heads/*", "refs/heads/main", true},
		{"*", "refs/heads/main", true},
	}

	for _, tt := range tests {
		got, err := matchGlob(tt.pattern, tt.value)
		if err != nil {
			t.Errorf("matchGlob(%q, %q) error: %v", tt.pattern, tt.value, err)
			continue
		}
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}
