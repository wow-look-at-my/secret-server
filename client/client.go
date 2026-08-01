// Package client is the Go client for secret-server's one public endpoint,
// GET /github/v1/secrets.
//
// It exists because the endpoint's contract is small but easy to get subtly
// wrong, and every consumer that reimplements it gets to make the same
// mistakes privately: quoting a 200 body into an error message (that body IS
// the secrets), treating an entitled-to-nothing 200 {} as success-with-a-
// missing-key, or caching a failed fetch so a restart-time outage never heals.
// One implementation, next to the server that defines the contract.
//
// The wire constants below are the server's own -- internal/database and
// internal/handlers take them from here -- so a client built against this
// package cannot drift from the server that ships it.
//
// Values are secrets. They are never logged and never put in an error string;
// errors name the SECRET, the URL and the HTTP status, and quote a body only
// when the status says it is an error rather than a payload.
//
// Typical use, aliased so call sites read as the service they talk to:
//
//	import secretserver "github.com/wow-look-at-my/secret-server/client"
//
//	c, err := secretserver.NewMachineToken(os.Getenv("SECRET_SERVER_TOKEN"))
//	if err != nil {
//	        return err
//	}
//	secrets := secretserver.NewCache(c, 0)
//	token, err := secrets.Secret(ctx, "PRIVATE_ORG_REPO_READ")
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is this org's secret-server deployment. Override it with
// WithBaseURL for another instance or a test server.
const DefaultBaseURL = "https://secrets.pazer.io"

// MachineTokenPrefix marks an admin-issued machine token. The server picks its
// validation path from the prefix, so a credential without it is validated as
// an OIDC JWT -- which is why NewMachineToken can reject a wrong-shaped
// credential at construction instead of leaving it to surface as a 401.
const MachineTokenPrefix = "sst_"

// SecretsPath is the one public route. Both credential types share it.
const SecretsPath = "/github/v1/secrets"

// DefaultTTL is how long Cache reuses a fetched secret set: short enough that
// a rotated credential heals without a redeploy, long enough that nothing
// hammers the server.
const DefaultTTL = 15 * time.Minute

// ErrNotEntitled reports that the fetch succeeded but the credential is not
// authorized for the requested secret. It is a CONFIGURATION answer, not a
// transport failure -- retrying changes nothing until an admin grants the
// secret to the credential -- and the two need different fixes, which is why
// they are different errors.
var ErrNotEntitled = errors.New("secret-server: credential is not entitled to that secret")

// Client fetches the secret set one credential is authorized for.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL points the client at a specific secret-server instance. An empty
// or whitespace-only url leaves DefaultBaseURL in place; a trailing slash is
// trimmed.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		if strings.TrimSpace(url) != "" {
			c.baseURL = strings.TrimRight(strings.TrimSpace(url), "/")
		}
	}
}

// WithHTTPClient overrides the HTTP client (timeouts, proxies, a test server's
// client). A nil h is ignored.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// New returns a Client for any bearer credential the endpoint accepts: a
// machine token or a GitHub Actions OIDC JWT. Use NewMachineToken when the
// credential is supposed to be a machine token and a wrong one should fail
// loudly at startup.
func New(token string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("secret-server: no bearer credential given")
	}
	c := &Client{
		baseURL: DefaultBaseURL,
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// NewMachineToken is New with the machine-token shape enforced. A deployment
// handed an OIDC JWT, a GitHub PAT or a truncated value fails here, naming the
// prefix, rather than an hour later as an unexplained 401.
func NewMachineToken(token string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(strings.TrimSpace(token), MachineTokenPrefix) {
		return nil, fmt.Errorf("secret-server: machine token must start with %q (the prefix selects the server's validation path; an OIDC JWT is not usable here)", MachineTokenPrefix)
	}
	return New(token, opts...)
}

// BaseURL reports the instance this client talks to. Useful in a startup log
// line; the credential is deliberately not exposed.
func (c *Client) BaseURL() string { return c.baseURL }

// Fetch returns every secret the credential is authorized for, as name ->
// plaintext value. A credential authorized for nothing yields an empty map and
// a nil error, which is what the server means by 200 {}.
func (c *Client) Fetch(ctx context.Context) (map[string]string, error) {
	url := c.baseURL + SecretsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("secret-server: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secret-server: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Only an ERROR body is quoted. A 200 body is the secrets.
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		msg := strings.TrimSpace(string(excerpt))
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("secret-server: GET %s: HTTP 401 (credential missing, revoked or malformed): %s", url, msg)
		}
		return nil, fmt.Errorf("secret-server: GET %s: HTTP %d: %s", url, resp.StatusCode, msg)
	}

	var secrets map[string]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&secrets); err != nil {
		// Deliberately not quoting the body: on 200 it is secret material.
		return nil, fmt.Errorf("secret-server: GET %s: response is not a JSON object of name -> value: %w", url, err)
	}
	if secrets == nil {
		secrets = map[string]string{}
	}
	return secrets, nil
}

// maxResponseBytes bounds a decode against a server (or a proxy in front of
// one) that answers with something unbounded.
const maxResponseBytes = 4 << 20

// Cache serves individual secrets from a fetch it reuses for a TTL.
//
// A failed fetch is deliberately NOT cached: the deployment that could not
// reach secret-server at startup is exactly the one that has to recover by
// itself, so the next caller retries rather than staying blind until someone
// restarts the process.
type Cache struct {
	client *Client
	ttl    time.Duration
	now    func() time.Time

	mu        sync.Mutex
	cached    map[string]string
	fetchedAt time.Time
}

// NewCache wraps a client with a TTL cache. A ttl <= 0 means DefaultTTL.
func NewCache(c *Client, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{client: c, ttl: ttl, now: time.Now}
}

// Secrets returns the whole authorized set, fetching (or re-fetching) as
// needed. The returned map is a copy: a caller mutating it cannot corrupt what
// the next caller reads.
func (p *Cache) Secrets(ctx context.Context) (map[string]string, error) {
	if p == nil || p.client == nil {
		return nil, errors.New("secret-server: not configured")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.refreshLocked(ctx); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(p.cached))
	for k, v := range p.cached {
		out[k] = v
	}
	return out, nil
}

// Secret returns one secret by name. A name the credential is not authorized
// for returns ErrNotEntitled.
func (p *Cache) Secret(ctx context.Context, name string) (string, error) {
	if p == nil || p.client == nil {
		return "", errors.New("secret-server: not configured")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.refreshLocked(ctx); err != nil {
		return "", err
	}
	v, ok := p.cached[name]
	if !ok || v == "" {
		return "", fmt.Errorf("%w: %s", ErrNotEntitled, name)
	}
	return v, nil
}

func (p *Cache) refreshLocked(ctx context.Context) error {
	if p.cached != nil && p.now().Sub(p.fetchedAt) < p.ttl {
		return nil
	}
	secrets, err := p.client.Fetch(ctx)
	if err != nil {
		return err
	}
	p.cached = secrets
	p.fetchedAt = p.now()
	return nil
}
