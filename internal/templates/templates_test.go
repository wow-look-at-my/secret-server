package templates

import (
	"html/template"
	"net/http/httptest"
	"testing"
	"time"

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

func TestTimeTag(t *testing.T) {
	ts := time.Date(2026, 7, 3, 14, 5, 9, 0, time.FixedZone("UTC+2", 2*3600))
	want := template.HTML(`<time datetime="2026-07-03T12:05:09Z">2026-07-03 12:05:09 UTC</time>`)

	assert.Equal(t, want, timeTag(ts), "time.Time is rendered in UTC")
	assert.Equal(t, want, timeTag(&ts), "*time.Time dereferences")

	var nilTime *time.Time
	assert.Equal(t, template.HTML(""), timeTag(nilTime), "nil *time.Time renders nothing")
	assert.Equal(t, template.HTML(""), timeTag("not a time"), "non-time values render nothing")
}

func TestRenderAuditLogTimestamps(t *testing.T) {
	tmpl, err := New("/admin", "test")
	require.Nil(t, err)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/audit", nil)
	tmpl.Render(rr, req, "audit_log.html", map[string]any{
		"Entries": []map[string]any{{
			"Timestamp":    time.Date(2026, 7, 3, 14, 5, 9, 0, time.UTC),
			"Action":       "secret.create",
			"ActorDisplay": "tester",
			"ResourceType": "secret",
			"Details":      "{}",
		}},
	})
	assert.Equal(t, 200, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `<time datetime="2026-07-03T14:05:09Z">2026-07-03 14:05:09 UTC</time>`)
	assert.Contains(t, body, `time[datetime]`, "layout foot ships the locale rewriter script")
}

func TestRenderMachineTokensListTimestamps(t *testing.T) {
	tmpl, err := New("/admin", "test")
	require.Nil(t, err)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/machine-tokens", nil)
	tmpl.Render(rr, req, "machine_tokens_list.html", map[string]any{
		"Tokens": []map[string]any{{
			"ID":          "tok1",
			"Name":        "hook",
			"TokenPrefix": "sst_abc",
			"CreatedAt":   time.Date(2026, 7, 3, 14, 5, 0, 0, time.UTC),
			"LastUsedAt":  (*time.Time)(nil),
		}},
	})
	assert.Equal(t, 200, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `<time datetime="2026-07-03T14:05:00Z">2026-07-03 14:05:00 UTC</time>`)
	assert.Contains(t, body, `<span class="empty">never</span>`, "nil LastUsedAt still shows never")
}
