package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wow-look-at-my/secret-server/internal/database"
)

func TestAgentHostPushProvenanceResolvesHumanForOIDCPolicy(t *testing.T) {
	env := setup(t)
	attachPolicyTo(
		t,
		env,
		"HUMAN_SECRET",
		"allowed",
		nil,
		"human-only",
		[]string{"acme/repo"},
		[]string{"refs/heads/main"},
		[]string{"id:6569500"},
	)
	machineToken, rec, err := env.db.CreateMachineToken("agent-host", nil, nil)
	require.NoError(t, err)

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	preflight := httptest.NewRequest(
		http.MethodHead,
		"/github/v1/push-provenance",
		nil,
	)
	preflight.Header.Set("Authorization", "Bearer "+machineToken)
	preflightResponse := httptest.NewRecorder()
	mux.ServeHTTP(preflightResponse, preflight)
	assert.Equal(t, http.StatusForbidden, preflightResponse.Code)

	require.NoError(t, env.db.SetMachineTokenGitHubAttestation(
		preflight.Context(),
		rec.ID,
		true,
	))

	body := `{"pushes":[{
		"repository":"acme/repo",
		"ref":"refs/heads/main",
		"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"github_user_id":6569500,
		"github_login":"PazerOP",
		"session_id":"session-1"
	}]}`
	attest := httptest.NewRequest(
		http.MethodPost,
		"/github/v1/push-provenance",
		strings.NewReader(body),
	)
	attest.Header.Set("Authorization", "Bearer "+machineToken)
	attest.Header.Set("Content-Type", "application/json")
	attestResponse := httptest.NewRecorder()
	mux.ServeHTTP(attestResponse, attest)
	require.Equal(t, http.StatusCreated, attestResponse.Code, attestResponse.Body.String())

	token := makeOIDCTokenWithActor(
		t,
		env.jwk,
		"acme/repo",
		"refs/heads/main",
		"agent-host[bot]",
	)
	fetch := httptest.NewRequest(http.MethodGet, "/github/v1/secrets", nil)
	fetch.Header.Set("Authorization", "Bearer "+token)
	fetchResponse := httptest.NewRecorder()
	mux.ServeHTTP(fetchResponse, fetch)
	require.Equal(t, http.StatusOK, fetchResponse.Code)

	var secrets map[string]string
	require.NoError(t, json.Unmarshal(fetchResponse.Body.Bytes(), &secrets))
	assert.Equal(t, "allowed", secrets["HUMAN_SECRET"])

	entries, err := env.audit.ListEntries(10, 0)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "secret.access.granted", entries[0].Action)
	assert.Equal(t, "6569500", entries[0].ActorID)
	assert.Contains(t, entries[0].Details, `"identity_source":"agent_host_push"`)
	assert.Contains(t, entries[0].Details, `"actor":"PazerOP"`)
	assert.Contains(t, entries[0].Details, `"oidc_actor":"agent-host[bot]"`)
	assert.Equal(t, "github.push.attested", entries[1].Action)
	assert.NotContains(t, entries[1].Details, machineToken)
}

func TestPushProvenanceRequiresExactRefAndSHA(t *testing.T) {
	env := setup(t)
	attachPolicyTo(
		t,
		env,
		"HUMAN_SECRET",
		"allowed",
		nil,
		"human-only",
		[]string{"acme/repo"},
		[]string{"refs/heads/main"},
		[]string{"PazerOP"},
	)
	_, rec, err := env.db.CreateMachineToken("agent-host", nil, nil)
	require.NoError(t, err)
	require.NoError(t, env.db.SetMachineTokenGitHubAttestation(
		context.Background(),
		rec.ID,
		true,
	))
	require.NoError(t, env.db.StoreGitHubPushProvenance(
		context.Background(),
		database.GitHubPushProvenance{
			Repository:     "acme/repo",
			Ref:            "refs/heads/main",
			SHA:            strings.Repeat("b", 40),
			GitHubUserID:   "6569500",
			GitHubLogin:    "PazerOP",
			MachineTokenID: rec.ID,
		},
	))

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)
	token := makeOIDCTokenWithActor(
		t,
		env.jwk,
		"acme/repo",
		"refs/heads/main",
		"agent-host[bot]",
	)
	req := httptest.NewRequest(http.MethodGet, "/github/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "{}", strings.TrimSpace(response.Body.String()))
}

func TestPushProvenancePreflightAndAuthentication(t *testing.T) {
	env := setup(t)
	token, rec, err := env.db.CreateMachineToken("agent-host", nil, nil)
	require.NoError(t, err)
	require.NoError(t, env.db.SetMachineTokenGitHubAttestation(
		context.Background(),
		rec.ID,
		true,
	))

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	for name, authorization := range map[string]struct {
		authorization string
		wantStatus    int
	}{
		"missing": {"", http.StatusUnauthorized},
		"invalid": {"Bearer sst_invalid", http.StatusUnauthorized},
		"valid":   {"Bearer " + token, http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodHead,
				"/github/v1/push-provenance",
				nil,
			)
			req.Header.Set("Authorization", authorization.authorization)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, req)
			assert.Equal(t, authorization.wantStatus, response.Code)
		})
	}
}

func TestPushProvenanceRejectsInvalidPayloads(t *testing.T) {
	env := setup(t)
	token, rec, err := env.db.CreateMachineToken("agent-host", nil, nil)
	require.NoError(t, err)
	require.NoError(t, env.db.SetMachineTokenGitHubAttestation(
		context.Background(),
		rec.ID,
		true,
	))

	h := NewPublicHandler(env.db, env.audit, env.oidc)
	mux := chi.NewRouter()
	h.Register(mux)

	valid := `{
		"repository":"acme/repo",
		"ref":"refs/heads/main",
		"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"github_user_id":6569500,
		"github_login":"PazerOP"
	}`
	tests := map[string]string{
		"malformed JSON":   `{`,
		"trailing JSON":    `{"pushes":[` + valid + `]} {}`,
		"unknown field":    `{"pushes":[],"unexpected":true}`,
		"empty list":       `{"pushes":[]}`,
		"invalid repo":     `{"pushes":[` + strings.Replace(valid, `"acme/repo"`, `"acme/repo.git"`, 1) + `]}`,
		"invalid ref":      `{"pushes":[` + strings.Replace(valid, `"refs/heads/main"`, `"main"`, 1) + `]}`,
		"invalid sha":      `{"pushes":[` + strings.Replace(valid, `"`+strings.Repeat("a", 40)+`"`, `"bad"`, 1) + `]}`,
		"invalid user ID":  `{"pushes":[` + strings.Replace(valid, "6569500", "0", 1) + `]}`,
		"invalid login":    `{"pushes":[` + strings.Replace(valid, `"PazerOP"`, `"bad login"`, 1) + `]}`,
		"invalid ref name": `{"pushes":[` + strings.Replace(valid, `"refs/heads/main"`, `"refs/heads/a..b"`, 1) + `]}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/github/v1/push-provenance",
				strings.NewReader(body),
			)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, req)
			assert.Equal(t, http.StatusBadRequest, response.Code)
		})
	}
}
