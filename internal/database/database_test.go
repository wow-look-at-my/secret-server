package database

import (
	"os"
	"testing"

	"github.com/wow-look-at-my/secret-server/internal/crypto"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	db, err := New(f.Name(), enc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSecretCRUD(t *testing.T) {
	db := testDB(t)

	// Create
	s, err := db.CreateSecret("API_KEY", "secret123", "myapp", "prod")
	if err != nil {
		t.Fatal(err)
	}
	if s.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if s.Key != "API_KEY" {
		t.Errorf("Key = %q, want %q", s.Key, "API_KEY")
	}

	// Get
	got, err := db.GetSecret(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected secret, got nil")
	}
	if got.Value != "secret123" {
		t.Errorf("Value = %q, want %q", got.Value, "secret123")
	}
	if got.Project != "myapp" {
		t.Errorf("Project = %q, want %q", got.Project, "myapp")
	}

	// List
	secrets, err := db.ListSecrets("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 {
		t.Fatalf("got %d secrets, want 1", len(secrets))
	}

	// List with filter
	secrets, err = db.ListSecrets("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 {
		t.Fatalf("got %d secrets, want 1", len(secrets))
	}
	secrets, err = db.ListSecrets("other", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 0 {
		t.Fatalf("got %d secrets, want 0", len(secrets))
	}

	// Update
	err = db.UpdateSecret(s.ID, "API_KEY", "newsecret", "myapp", "prod")
	if err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetSecret(s.ID)
	if got.Value != "newsecret" {
		t.Errorf("Value after update = %q, want %q", got.Value, "newsecret")
	}

	// Delete
	err = db.DeleteSecret(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err = db.GetSecret(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestGetSecretNotFound(t *testing.T) {
	db := testDB(t)
	got, err := db.GetSecret("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil for nonexistent secret")
	}
}

func TestSecretUniqueConstraint(t *testing.T) {
	db := testDB(t)
	_, err := db.CreateSecret("KEY", "val1", "proj", "env")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateSecret("KEY", "val2", "proj", "env")
	if err == nil {
		t.Fatal("expected unique constraint error")
	}
}

func TestGetSecretsByProjectEnv(t *testing.T) {
	db := testDB(t)
	db.CreateSecret("A", "1", "proj", "prod")
	db.CreateSecret("B", "2", "proj", "prod")
	db.CreateSecret("C", "3", "proj", "dev")
	db.CreateSecret("D", "4", "other", "prod")

	secrets, err := db.GetSecretsByProjectEnv("proj", "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets, want 2", len(secrets))
	}
	if secrets["A"] != "1" || secrets["B"] != "2" {
		t.Errorf("unexpected secrets: %v", secrets)
	}
}

func TestPolicyCRUD(t *testing.T) {
	db := testDB(t)

	// Create
	p, err := db.CreatePolicy("Allow prod", "myorg/*", "refs/heads/main", "myapp", "prod")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	// Get
	got, err := db.GetPolicy(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected policy, got nil")
	}
	if got.Name != "Allow prod" {
		t.Errorf("Name = %q, want %q", got.Name, "Allow prod")
	}
	if got.RepositoryPattern != "myorg/*" {
		t.Errorf("RepositoryPattern = %q", got.RepositoryPattern)
	}

	// List
	policies, err := db.ListPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies, want 1", len(policies))
	}

	// Update
	err = db.UpdatePolicy(p.ID, "Updated", "other/*", "*", "myapp", "staging")
	if err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetPolicy(p.ID)
	if got.Name != "Updated" {
		t.Errorf("Name after update = %q", got.Name)
	}
	if got.Environment != "staging" {
		t.Errorf("Environment after update = %q", got.Environment)
	}

	// Delete
	err = db.DeletePolicy(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err = db.GetPolicy(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestGetPolicyNotFound(t *testing.T) {
	db := testDB(t)
	got, err := db.GetPolicy("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil for nonexistent policy")
	}
}

func TestMatchingPolicies(t *testing.T) {
	db := testDB(t)
	db.CreatePolicy("p1", "myorg/*", "refs/heads/main", "app", "prod")
	db.CreatePolicy("p2", "myorg/specific", "*", "app", "dev")
	db.CreatePolicy("p3", "other/*", "*", "other", "prod")

	// Should match p1 only
	matched, err := db.MatchingPolicies("myorg/repo", "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 || matched[0].Name != "p1" {
		t.Errorf("expected p1, got %v", matched)
	}

	// Should match p1 and p2
	matched, err = db.MatchingPolicies("myorg/specific", "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matched))
	}

	// No match
	matched, err = db.MatchingPolicies("unknown/repo", "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matched))
	}
}

func TestDashboardStats(t *testing.T) {
	db := testDB(t)
	db.CreateSecret("A", "1", "proj", "prod")
	db.CreateSecret("B", "2", "proj", "prod")
	db.CreateSecret("C", "3", "proj", "dev")
	db.CreatePolicy("p1", "*", "*", "proj", "prod")

	stats, err := db.GetDashboardStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalSecrets != 3 {
		t.Errorf("TotalSecrets = %d, want 3", stats.TotalSecrets)
	}
	if stats.TotalPolicies != 1 {
		t.Errorf("TotalPolicies = %d, want 1", stats.TotalPolicies)
	}
	if len(stats.Projects) != 2 {
		t.Errorf("Projects = %d, want 2", len(stats.Projects))
	}
}
