package templates

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTemplates(t *testing.T) {
	tmpl, err := New("/admin", "test")
	require.Nil(t, err)
	require.NotNil(t, tmpl)
}

func TestRenderDashboard(t *testing.T) {
	tmpl, err := New("/admin", "test")
	require.Nil(t, err)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/", nil)
	data := map[string]any{
		"TotalSecrets":     5,
		"TotalGroups":      2,
		"TotalPolicies":    3,
		"UnreachableCount": 0,
		"Roots":            []any{},
	}
	tmpl.Render(rr, req, "dashboard.html", data)

	assert.Equal(t, 200, rr.Code)
	assert.NotEqual(t, 0, rr.Body.Len())
}

func TestRenderSecretsBrowse(t *testing.T) {
	tmpl, _ := New("/admin", "test")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/secrets", nil)
	tmpl.Render(rr, req, "secrets_browse.html", map[string]any{
		"Roots": []any{},
	})
	assert.Equal(t, 200, rr.Code)
}

func TestRenderNodeFormNewSecret(t *testing.T) {
	tmpl, _ := New("/admin", "test")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/secrets/new", nil)
	tmpl.Render(rr, req, "node_form.html", map[string]any{
		"IsNew":    true,
		"Kind":     "secret",
		"ParentID": "",
		"Groups":   []any{},
	})
	assert.Equal(t, 200, rr.Code)
}

func TestRenderNodeFormNewGroup(t *testing.T) {
	tmpl, _ := New("/admin", "test")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/secrets/new?kind=group", nil)
	tmpl.Render(rr, req, "node_form.html", map[string]any{
		"IsNew":    true,
		"Kind":     "group",
		"ParentID": "",
		"Groups":   []any{},
	})
	assert.Equal(t, 200, rr.Code)
}

func TestRenderPoliciesList(t *testing.T) {
	tmpl, _ := New("/admin", "test")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/policies", nil)
	tmpl.Render(rr, req, "policies_list.html", []any{})
	assert.Equal(t, 200, rr.Code)
}

func TestRenderPolicyForm(t *testing.T) {
	tmpl, _ := New("/admin", "test")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/policies/new", nil)
	tmpl.Render(rr, req, "policy_form.html", map[string]any{
		"IsNew": true,
	})
	assert.Equal(t, 200, rr.Code)
}
