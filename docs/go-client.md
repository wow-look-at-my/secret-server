# The Go client (`github.com/wow-look-at-my/secret-server/client`)

## Why it exists

The public API is one route, but its contract has edges that every
reimplementation gets to discover privately. webhook-runner wrote its own and
hit all of them; this package is that code moved next to the server that
defines the contract, so the next consumer imports it instead.

The edges, and what the package does about each:

- **A 200 body is secret material.** A decode failure must not quote the body
  into an error, because errors travel to logs, dashboards and, in
  webhook-runner's case, an operator-facing attention surface that is required
  to be value-free. The client quotes a body only on a non-200, where the body
  is the server's own `{"error": ...}`.
- **200 `{}` is an answer, not a failure.** A credential authorized for nothing
  gets an empty object with HTTP 200. That is a *configuration* state — go
  grant the secret — and it must not read as an outage. Asking `Cache` for a
  name it cannot see returns `ErrNotEntitled`, matchable with `errors.Is` and
  distinct from every transport error.
- **A failed fetch must not be cached.** The deployment that could not reach
  secret-server at startup is exactly the one that has to recover by itself. If
  a failure were cached for the TTL, a restart during a brief outage would
  leave the process blind until someone restarted it again.
- **The `sst_` prefix is load-bearing.** The server picks its validation path
  from it: a credential without the prefix is validated as an OIDC JWT and
  rejected. `NewMachineToken` fails at construction naming the prefix, so a
  deployment handed a PAT or a truncated value dies at boot with the reason
  instead of answering 401 an hour later, once, in a background poll.

## The contract lives here, not in two places

`MachineTokenPrefix` and `SecretsPath` are declared in this package.
`internal/database` mints tokens with the former and `internal/handlers`
registers the route with the latter. A consumer therefore compiles against the
same symbols the server runs on, and there is no second copy to drift.

`internal/handlers/client_contract_test.go` closes the remaining gap: unit
tests on each side can both pass while the two disagree about the wire, so that
test drives the real client against the real handler with a real machine token
over a real `httptest` server — a fetch, the authorized-for-nothing case, and a
revoked token.

## Shape

```go
import secretserver "github.com/wow-look-at-my/secret-server/client"

c, err := secretserver.NewMachineToken(os.Getenv("SECRET_SERVER_TOKEN"))
// or secretserver.New(oidcJWT) — the endpoint takes either credential type

secrets := secretserver.NewCache(c, 0) // 0 = DefaultTTL (15m)
tok, err := secrets.Secret(ctx, "PRIVATE_ORG_REPO_READ")
switch {
case errors.Is(err, secretserver.ErrNotEntitled):
        // grant the secret to this credential; retrying will not help
case err != nil:
        // transport/server failure; the next call retries
}
```

Options are `WithBaseURL` (defaults to this org's instance) and
`WithHTTPClient`. `Client.Fetch` returns the whole authorized set;
`Cache.Secrets` returns a copy of it, so a caller that mutates what it got
cannot corrupt what the next caller reads.

The package imports nothing outside the standard library. That is deliberate:
a client a consumer hesitates to import because of what it drags in is a
client that gets reimplemented, which is the problem this package exists to
end.

## Consumers

- `webhook-runner` — reads `PRIVATE_ORG_REPO_READ` to authenticate the GitHub
  API calls its CI-gated hooks-repo reload depends on. Its own
  `internal/secretserver` was the prototype for this package and is gone.
