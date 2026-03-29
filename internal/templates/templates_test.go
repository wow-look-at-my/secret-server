package templates

import (
	"net/http/httptest"
	"testing"
	"github.com/wow-look-at-my/testify/assert"
	"github.com/wow-look-at-my/testify/require"
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
	data := struct {
		TotalSecrets	int
		TotalPolicies	int
		Projects	[]struct {
			Project		string
			Environment	string
			SecretCount	int
		}
	}{
		TotalSecrets:	5,
		TotalPolicies:	2,
	}
	tmpl.Render(rr, req, "dashboard.html", data)

	assert.Equal(t, 200, rr.Code)

	body := rr.Body.String()
	require.NotEqual(t, 0, len(body))

}

func TestRenderSecretsList(t *testing.T) {
	tmpl, _ := New("/admin", "test")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/secrets", nil)
	tmpl.Render(rr, req, "secrets_list.html", map[string]any{
		"Secrets":	[]any{},
		"Project":	"",
		"Environment":	"",
	})
	assert.Equal(t, 200, rr.Code)

}

func TestRenderSecretForm(t *testing.T) {
	tmpl, _ := New("/admin", "test")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/secrets/new", nil)
	tmpl.Render(rr, req, "secret_form.html", map[string]any{
		"IsNew": true,
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
