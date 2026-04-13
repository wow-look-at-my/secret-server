# secret-server

Self-hosted secrets manager for homelab use. Single Go binary with SQLite storage, two auth zones, and a web UI.

## Architecture

| Zone | Routes | Auth | Access |
|------|--------|------|--------|
| GitHub API | `GET /github/v1/secrets` | GitHub Actions OIDC JWT | Read-only — vend secrets matching policies |
| Admin API | `/admin/v1/*` | Cloudflare Access JWT | Create, update, delete secrets, policies, and environments |
| Admin UI | `/admin/*` | Cloudflare Access JWT | Web UI for managing secrets, policies, and environments |

Two path prefixes for Cloudflare Access: protect `/admin/*`, bypass `/github/*`. The GitHub API validates OIDC tokens directly. Admin routes are protected by Cloudflare Access (the server validates CF JWTs as defense-in-depth). The root path `/` redirects to the admin UI. `GET /health` is available for Docker/uptime checks (not routed through CF Access).

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

Policies control which GitHub Actions workflows can access which secrets. Each policy has a **mode** that determines how authorization is performed:

### Pattern mode (default)

The traditional mode where the server checks repo/ref/actor patterns:

- **Repository patterns** — one or more glob patterns matching repository names (e.g. `myorg/*`, `myorg/api-*`). At least one is required. A request matches if the repository matches **any** of the listed globs.
- **Ref patterns** — glob patterns matching git refs (e.g. `refs/heads/main`, `refs/tags/v*`). Leave empty or use `*` to allow any branch or tag.
- **Actor patterns** — glob patterns matching the GitHub username that triggered the workflow (e.g. `deploy-*`). Leave empty or use `*` to allow any actor.
- **Environment** — which secrets the policy grants access to (selected from managed environments, referenced by UUID).

A policy matches a request iff the repository matches **any** repository pattern AND the ref matches **any** ref pattern AND the actor matches **any** actor pattern.

### GitHub Actions Environment mode

An alternative mode that trusts GitHub's [environment deployment protection rules](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) instead of doing its own ref/actor filtering:

- **Repository patterns** — same as pattern mode, checked against the OIDC token's `repository` claim.
- **GitHub environment name** — the exact name of the GitHub Actions environment (e.g. `production`). Must match the `environment` claim in the OIDC token.
- Ref and actor patterns are **ignored** — GitHub enforces branch restrictions, required reviewers, and wait timers for the environment.

This mode is useful when you want to leverage GitHub's native environment protection rules (branch policies, required reviewers, wait timers) rather than duplicating them in the secret server.

**Security tradeoff:** Repo admins can modify environment protection rules, so this mode delegates trust to GitHub and repo admins. Use pattern mode when centralized control is required.

### Common fields

In the web UI, enter one pattern per line in each textarea. In the JSON admin API:

- `mode` — `"pattern"` (default) or `"github-environment"`
- `repository_patterns` — string array of glob patterns
- `ref_patterns`, `actor_patterns` — string arrays (pattern mode only)
- `github_environment` — string (required for github-environment mode)
- `environment_id` — UUID of the managed environment whose secrets this policy grants access to

When a GitHub Actions workflow requests secrets, the server:
1. Validates the OIDC token
2. Finds policies matching the token's claims (mode-dependent matching)
3. Returns secrets from matching project/environment pairs

On upgrade from older versions, existing policies default to pattern mode. The `mode` and `github_environment` columns are automatically added.

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
