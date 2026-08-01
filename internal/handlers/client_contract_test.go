package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wow-look-at-my/secret-server/client"
)

// The published client is compiled against constants and a response shape this
// server defines. Unit tests on either side can both pass while the two
// disagree, so these drive the REAL client against the REAL handler: what
// breaks a consumer breaks this test first.

func TestPublishedClientFetchesThroughTheRealHandler(t *testing.T) {
	env := setup(t)
	nodeID := createSecret(t, env, "PRIVATE_ORG_REPO_READ", "ghp_example")
	token, _, err := env.db.CreateMachineToken("webhook-runner", nil, []string{nodeID})
	require.NoError(t, err)

	mux := chi.NewRouter()
	NewPublicHandler(env.db, env.audit, env.oidc).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// NewMachineToken enforces the prefix the server mints, so this also pins
	// client.MachineTokenPrefix against database.MachineTokenPrefix.
	c, err := client.NewMachineToken(token, client.WithBaseURL(srv.URL), client.WithHTTPClient(srv.Client()))
	require.NoError(t, err)

	secrets, err := c.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ghp_example", secrets["PRIVATE_ORG_REPO_READ"])

	got, err := client.NewCache(c, 0).Secret(context.Background(), "PRIVATE_ORG_REPO_READ")
	require.NoError(t, err)
	assert.Equal(t, "ghp_example", got)
}

// An authorized-for-nothing credential is the case a consumer must be able to
// tell apart from an outage, and the server expresses it as 200 {}.
func TestPublishedClientSeesEntitledToNothingAsSuchAndBadTokensAs401(t *testing.T) {
	env := setup(t)
	token, _, err := env.db.CreateMachineToken("granted-nothing", nil, nil)
	require.NoError(t, err)

	mux := chi.NewRouter()
	NewPublicHandler(env.db, env.audit, env.oidc).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := client.NewMachineToken(token, client.WithBaseURL(srv.URL), client.WithHTTPClient(srv.Client()))
	require.NoError(t, err)

	secrets, err := c.Fetch(context.Background())
	require.NoError(t, err, "authorized for nothing is a configuration answer, not a transport failure")
	assert.Empty(t, secrets)

	_, err = client.NewCache(c, 0).Secret(context.Background(), "PRIVATE_ORG_REPO_READ")
	require.ErrorIs(t, err, client.ErrNotEntitled)

	revoked, err := client.NewMachineToken(client.MachineTokenPrefix+"definitely-not-real",
		client.WithBaseURL(srv.URL), client.WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	_, err = revoked.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

// The client builds its URL from client.SecretsPath; the route must be the
// path a consumer's compiled-in constant asks for.
func TestSecretsPathIsTheServedRoute(t *testing.T) {
	assert.Equal(t, GitHubPrefix+"/secrets", client.SecretsPath)
}
