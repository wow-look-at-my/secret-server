package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testClient(t *testing.T, srv *httptest.Server, token string) *Client {
	t.Helper()
	c, err := NewMachineToken(token, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	return c
}

// The one route, the one credential shape, the one response shape.
func TestFetchSendsTheCredentialAndParsesTheSecretSet(t *testing.T) {
	var gotPath, gotAuth, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotAccept = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"PRIVATE_ORG_REPO_READ":"ghp_example","OTHER":"x"}`))
	}))
	defer srv.Close()

	secrets, err := testClient(t, srv, "sst_abc").Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, SecretsPath, gotPath)
	assert.Equal(t, "Bearer sst_abc", gotAuth)
	assert.Equal(t, "application/json", gotAccept)
	assert.Equal(t, "ghp_example", secrets["PRIVATE_ORG_REPO_READ"])
}

// An OIDC JWT is the endpoint's other credential type, so the general
// constructor must not impose the machine-token shape on it.
func TestNewAcceptsAnyBearerCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"A":"1"}`))
	}))
	defer srv.Close()

	c, err := New("eyJhbGciOiJSUzI1NiJ9.e30.sig", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	require.NoError(t, err)

	secrets, err := c.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "1", secrets["A"])
}

func TestNewRejectsAnEmptyCredential(t *testing.T) {
	_, err := New("   ")
	require.Error(t, err)
}

// The prefix selects the server's validation path, so a credential without it
// would be validated as an OIDC JWT and rejected. Catching it at construction
// means the message says WHY instead of surfacing as a 401 an hour later.
func TestNewMachineTokenRequiresThePrefix(t *testing.T) {
	_, err := NewMachineToken("ghp_not_a_machine_token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), MachineTokenPrefix, "the error must name the prefix")

	_, err = NewMachineToken("  ")
	require.Error(t, err)
}

func TestBaseURLDefaultsAndNormalizes(t *testing.T) {
	c, err := New("sst_abc")
	require.NoError(t, err)
	assert.Equal(t, DefaultBaseURL, c.BaseURL())

	trailing, err := New("sst_abc", WithBaseURL("https://example.test/"))
	require.NoError(t, err)
	assert.Equal(t, "https://example.test", trailing.BaseURL())

	blank, err := New("sst_abc", WithBaseURL("   "))
	require.NoError(t, err)
	assert.Equal(t, DefaultBaseURL, blank.BaseURL(), "a blank override must not erase the default")

	nilHTTP, err := New("sst_abc", WithHTTPClient(nil))
	require.NoError(t, err)
	assert.NotNil(t, nilHTTP.http)
}

// A credential authorized for nothing is a 200 with {} -- a configuration
// answer, not a transport failure, and the distinction is what tells an
// operator to go grant the secret rather than go debug the network.
func TestEntitledToNothingIsNotATransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := testClient(t, srv, "sst_abc")

	secrets, err := c.Fetch(context.Background())
	require.NoError(t, err)
	assert.Empty(t, secrets)

	_, err = NewCache(c, time.Minute).Secret(context.Background(), "PRIVATE_ORG_REPO_READ")
	require.ErrorIs(t, err, ErrNotEntitled)
	assert.Contains(t, err.Error(), "PRIVATE_ORG_REPO_READ")
}

// A JSON null body decodes to a nil map; callers must never have to nil-check.
func TestNullBodyYieldsAnEmptyMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`null`))
	}))
	defer srv.Close()

	secrets, err := testClient(t, srv, "sst_abc").Fetch(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, secrets)
	assert.Empty(t, secrets)
}

func TestUnauthorizedNamesTheCause(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer srv.Close()

	_, err := testClient(t, srv, "sst_abc").Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "revoked")
	assert.Contains(t, err.Error(), "invalid token", "an ERROR body is safe to quote and says what went wrong")
}

func TestOtherStatusesCarryTheCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`upstream down`))
	}))
	defer srv.Close()

	_, err := testClient(t, srv, "sst_abc").Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestRequestErrorsAreWrapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening any more

	c, err := New("sst_abc", WithBaseURL(url))
	require.NoError(t, err)

	_, err = c.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret-server: GET ")

	// A context the caller already cancelled fails before the request is sent.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Fetch(ctx)
	require.Error(t, err)
}

// Secret VALUES must never reach an error string: errors travel to logs and to
// operator-facing surfaces, which are required to be value-free.
func TestErrorsNeverCarrySecretValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A 200 whose body is not the expected shape: the parse error must not
		// quote it, because on 200 the body is secret material.
		_, _ = w.Write([]byte(`["ghp_SUPERSECRET_VALUE"]`))
	}))
	defer srv.Close()

	_, err := testClient(t, srv, "sst_abc").Fetch(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SUPERSECRET")
}

// The cache exists to bound request volume, not to pin a value forever.
func TestCacheReusesWithinTTLAndRefetchesAfter(t *testing.T) {
	var calls int
	value := "first"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"PRIVATE_ORG_REPO_READ":"` + value + `"}`))
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0)
	p := NewCache(testClient(t, srv, "sst_abc"), time.Minute)
	p.now = func() time.Time { return now }

	for range 3 {
		got, err := p.Secret(context.Background(), "PRIVATE_ORG_REPO_READ")
		require.NoError(t, err)
		assert.Equal(t, "first", got)
	}
	assert.Equal(t, 1, calls)

	// A rotated credential must heal without a redeploy.
	value = "rotated"
	now = now.Add(2 * time.Minute)
	got, err := p.Secret(context.Background(), "PRIVATE_ORG_REPO_READ")
	require.NoError(t, err)
	assert.Equal(t, "rotated", got)
	assert.Equal(t, 2, calls)
}

// A failed fetch must not be sticky: the deployment that could not reach
// secret-server at startup is exactly the one that must recover by itself.
func TestCacheDoesNotCacheFailures(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"PRIVATE_ORG_REPO_READ":"ghp_example"}`))
	}))
	defer srv.Close()

	p := NewCache(testClient(t, srv, "sst_abc"), time.Hour)
	_, err := p.Secret(context.Background(), "PRIVATE_ORG_REPO_READ")
	require.Error(t, err)

	got, err := p.Secret(context.Background(), "PRIVATE_ORG_REPO_READ")
	require.NoError(t, err)
	assert.Equal(t, "ghp_example", got)
}

// Secrets hands out a copy, so a caller that mutates what it got cannot
// corrupt what the next caller reads out of the same cached fetch.
func TestSecretsReturnsACopy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"A":"1"}`))
	}))
	defer srv.Close()

	p := NewCache(testClient(t, srv, "sst_abc"), time.Hour)
	first, err := p.Secrets(context.Background())
	require.NoError(t, err)
	first["A"] = "tampered"
	delete(first, "A")

	second, err := p.Secrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "1", second["A"])
}

func TestCacheFailureIsReportedByBothAccessors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewCache(testClient(t, srv, "sst_abc"), time.Hour)
	_, err := p.Secrets(context.Background())
	require.Error(t, err)
	_, err = p.Secret(context.Background(), "A")
	require.Error(t, err)
}

func TestZeroTTLMeansTheDefault(t *testing.T) {
	p := NewCache(nil, 0)
	assert.Equal(t, DefaultTTL, p.ttl)
}

// A nil or unconfigured cache answers rather than panicking: consumers wire it
// from configuration that may be absent.
func TestNilCacheIsSafe(t *testing.T) {
	var p *Cache
	_, err := p.Secret(context.Background(), "X")
	require.Error(t, err)
	_, err = p.Secrets(context.Background())
	require.Error(t, err)

	empty := &Cache{}
	_, err = empty.Secret(context.Background(), "X")
	require.Error(t, err)
	_, err = empty.Secrets(context.Background())
	require.Error(t, err)
}

func TestErrNotEntitledIsMatchable(t *testing.T) {
	assert.True(t, errors.Is(fmtErrNotEntitled(), ErrNotEntitled))
}

func fmtErrNotEntitled() error {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"OTHER":"x"}`))
	}))
	defer srv.Close()

	c, err := New("sst_abc", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	if err != nil {
		return err
	}
	_, err = NewCache(c, time.Minute).Secret(context.Background(), "MISSING")
	return err
}
