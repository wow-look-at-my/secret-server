# secret-server

Self-hosted secrets manager for homelab use. Single Go binary with SQLite storage, two auth zones, and a web UI.

## Architecture

| Zone | Routes | Auth | Access |
|------|--------|------|--------|
| GitHub API | `GET /github/v1/secrets` | GitHub Actions OIDC JWT **or** machine token | Read-only — vend secrets matching policies (OIDC) or the token's environment (machine token) |
| Admin API | `/admin/v1/*` | Cloudflare Access JWT | Create, update, delete secrets, policies, environments, and machine tokens |
| Admin UI | `/admin/*` | Cloudflare Access JWT | Web UI for managing secrets, policies, environments, and machine tokens |

Two path prefixes for Cloudflare Access: protect `/admin/*`, bypass `/github/*`. The GitHub API validates OIDC tokens directly. Admin routes are protected by Cloudflare Access (the server validates CF JWTs as defense-in-depth). The root path `/` redirects to the admin UI. `GET /health` is available for Docker/uptime checks (not routed through CF Access).

## Machine Tokens

GitHub Actions OIDC is the right credential for a workflow, but some clients can't present an OIDC token — e.g. a [webhook-runner](https://github.com/wow-look-at-my/webhook-runner) hook running in a plain Docker container. **Machine tokens** fill that gap: a long-lived bearer credential, bound to exactly one environment, that a non-Actions client presents to the *same* `GET /github/v1/secrets` endpoint.

- **Shape:** `sst_<random>`. The server inspects the bearer token — the `sst_` prefix routes it to machine-token validation; anything else is validated as an OIDC JWT. Both share one route, so there is no extra Cloudflare Access bypass path to configure.
- **Storage:** only the token's SHA-256 hash is stored. The plaintext is shown **once**, at creation, and cannot be recovered — lose it and you revoke + reissue.
- **Access:** a machine token vends every secret in its bound environment (no repo/ref/actor policy match — the token *is* the grant). Scope it by putting only what that client needs in its environment.
- **Management:** create, list (by name + prefix), and revoke tokens on the **Machine Tokens** page in the admin UI, or via `POST/GET/DELETE /admin/v1/machine-tokens` in the admin API. `POST` returns `{"id","token"}` — the only time the token is exposed.
- **Audit:** every machine-token vend is recorded as a `secret.access` entry with actor type `machine_token` (and the token's name), the same as an OIDC `secret.access`. Denied attempts (unknown/revoked token) are `secret.access.denied`.

Example fetch (the bound environment's secrets come back as a JSON object):

```bash
curl -fsSL -H "Authorization: Bearer $SECRET_SERVER_TOKEN" \
  https://secrets.example.com/github/v1/secrets
# {"GITHUB_APP_PRIVATE_KEY":"-----BEGIN ...","OTHER_SECRET":"..."}
```

Treat the token as sensitive: it is a single bearer factor to its environment's secrets. It is, however, network-gated (only useful against your secret-server), policy-free but environment-scoped, centrally revocable in one click, and every use is audited — which is why it is a better home for a high-value key than scattering that key across client hosts/configs.

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENCRYPTION_KEY` | Yes | — | 32-byte hex-encoded AES-256 key (64 hex chars) |
| `CF_ACCESS_TEAM_DOMAIN` | Yes | — | Cloudflare Access team domain (e.g. `myteam`) |
| `CF_ACCESS_ADMIN_AUDIENCE` | Yes | — | Cloudflare Access application audience tag |
| `OIDC_AUDIENCE` | Yes | — | Expected audience for GitHub OIDC tokens |
| `LISTEN_ADDR` | No | `:8080` | Server listen address |
| `DATABASE_PATH` | No | `./secrets.db` | Path to SQLite database file |
| `AUDIT_DATABASE_PATH` | No | `./audit.db` | Path to audit log SQLite database (separate from secrets DB) |
| `LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |

Generate an encryption key:

```bash
openssl rand -hex 32
```

## Running

### Docker Compose

```bash
cp .env.example .env  # fill in values
docker compose up -d
```

### Binary

```bash
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
export CF_ACCESS_TEAM_DOMAIN="myteam"
export CF_ACCESS_ADMIN_AUDIENCE="your-cf-audience"
./secret-server
```

## GitHub Action

The composite action that fetches secrets from this server lives in [`wow-look-at-my/actions`](https://github.com/wow-look-at-my/actions/tree/master/secret-server):

```yaml
permissions:
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: wow-look-at-my/actions@secret-server#latest
        id: secrets

      # Secrets are exported as environment variables
      - run: echo "Got $DB_URL"
```

It requests a GitHub OIDC token, sends it to this server's `/github/v1/secrets` endpoint, and exports returned secrets as masked environment variables. See the [action README](https://github.com/wow-look-at-my/actions/blob/master/secret-server/README.md) for full input/output documentation.

## Audit Log

All state-changing operations are recorded in a separate SQLite database (`audit.db` by default). This includes:

- **Secret access** — which GitHub Actions repository/ref/workflow fetched secrets, and which policies matched
- **Secret management** — create, update, delete operations by admin users
- **Policy management** — create, update, delete operations by admin users
- **Environment management** — create, update, delete operations by admin users

The audit log is isolated from the secrets database to prevent corruption of credential data during hardware or power failures. View the audit log at `/ui/audit`.

## Environments

Environments are managed project/environment pairs (e.g. `myapp`/`prod`, `myapp`/`staging`) with UUID primary keys. They must be created on the Environments page before they can be used. Secrets and policies reference environments by `environment_id` (foreign key), not by string columns. This means environments can be renamed freely — all referencing secrets and policies automatically reflect the new name.

On upgrade from older versions, the schema is automatically migrated: existing project/environment string columns are replaced with `environment_id` foreign keys in a transaction.

## Access Policies

Policies control which GitHub Actions workflows can access which secrets. Each policy specifies:

- **Repository patterns** — one or more glob patterns matching repository names (e.g. `myorg/*`, `myorg/api-*`). At least one is required. A request matches if the repository matches **any** of the listed globs.
- **Ref patterns** — glob patterns matching git refs (e.g. `refs/heads/main`, `refs/tags/v*`). Leave empty or use `*` to allow any branch or tag.
- **Actor patterns** — glob patterns matching the GitHub username that triggered the workflow (e.g. `deploy-*`). Leave empty or use `*` to allow any actor.
- **Environment** — which secrets the policy grants access to (selected from managed environments, referenced by UUID).

A policy matches a request iff the repository matches **any** repository pattern AND the ref matches **any** ref pattern AND the actor matches **any** actor pattern.

In the web UI, enter one pattern per line in each textarea. In the JSON admin API, each field is a string array: `repository_patterns`, `ref_patterns`, `actor_patterns`.

When a GitHub Actions workflow requests secrets, the server:
1. Validates the OIDC token
2. Finds policies matching the token's repository, ref, and actor claims
3. Returns secrets from matching project/environment pairs

On upgrade from older versions, existing single-pattern columns are automatically migrated to the new JSON-array columns in-place; existing values become single-element arrays with no change in behavior.

## Cloudflare Access Setup

1. Create a self-hosted application in Cloudflare Access
2. Set the application URL to cover `/admin/*` (covers both the API and web UI)
3. Add a bypass rule for `/github/*` (covers the OIDC API and health check)
4. Configure the `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_ADMIN_AUDIENCE` env vars

## Dependencies

| Package | License | Purpose |
|---------|---------|---------|
| [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) | BSD-3-Clause | Pure-Go SQLite driver |
| [github.com/google/uuid](https://pkg.go.dev/github.com/google/uuid) | BSD-3-Clause | UUID generation |
| [github.com/go-jose/go-jose/v4](https://pkg.go.dev/github.com/go-jose/go-jose/v4) | Apache-2.0 | JWT/JWKS validation |

All other functionality uses the Go standard library.
