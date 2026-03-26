package templates

import (
	"net/http/httptest"
	"testing"
)

func TestNewTemplates(t *testing.T) {
	tmpl, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil templates")
	}
}

func TestRenderDashboard(t *testing.T) {
	tmpl, err := New()
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	data := struct {
		TotalSecrets  int
		TotalPolicies int
		Projects      []struct {
			Project     string
			Environment string
			SecretCount int
		}
	}{
		TotalSecrets:  5,
		TotalPolicies: 2,
	}
	tmpl.Render(rr, "dashboard.html", data)

	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if len(body) == 0 {
		t.Fatal("empty body")
	}
}

func TestRenderSecretsList(t *testing.T) {
	tmpl, _ := New()
	rr := httptest.NewRecorder()
	tmpl.Render(rr, "secrets_list.html", map[string]any{
		"Secrets":     []any{},
		"Project":     "",
		"Environment": "",
	})
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestRenderSecretForm(t *testing.T) {
	tmpl, _ := New()
	rr := httptest.NewRecorder()
	tmpl.Render(rr, "secret_form.html", map[string]any{
		"IsNew": true,
	})
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestRenderPoliciesList(t *testing.T) {
	tmpl, _ := New()
	rr := httptest.NewRecorder()
	tmpl.Render(rr, "policies_list.html", []any{})
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestRenderPolicyForm(t *testing.T) {
	tmpl, _ := New()
	rr := httptest.NewRecorder()
	tmpl.Render(rr, "policy_form.html", map[string]any{
		"IsNew": true,
	})
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}
