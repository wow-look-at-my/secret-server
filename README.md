# secret-server

Self-hosted secrets manager for homelab use. Single Go binary with SQLite storage, two auth zones, and a web UI.

## Architecture

| Zone | Routes | Auth | Access |
|------|--------|------|--------|
| GitHub API | `POST /github/v1/secrets` | GitHub Actions OIDC JWT | Read-only — vend secrets matching policies |
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

Use the composite action to fetch secrets in GitHub Actions workflows:

```yaml
permissions:
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: wow-look-at-my/secret-server@main
        id: secrets
        with:
          url: https://secrets.example.com
          audience: https://secrets.example.com  # optional, defaults to url

      # Secrets are exported as environment variables
      - run: echo "Got $DB_URL"
```

The action requests a GitHub OIDC token, sends it to the server's public API, and exports returned secrets as environment variables.

## Audit Log

All state-changing operations are recorded in a separate SQLite database (`audit.db` by default). This includes:

- **Secret access** — which GitHub Actions repository/ref/workflow fetched secrets, and which policies matched
- **Secret management** — create, update, delete operations by admin users
- **Policy management** — create, update, delete operations by admin users
- **Environment management** — create, delete operations by admin users

The audit log is isolated from the secrets database to prevent corruption of credential data during hardware or power failures. View the audit log at `/ui/audit`.

## Environments

Environments are managed project/environment pairs (e.g. `myapp`/`prod`, `myapp`/`staging`). They must be created on the Environments page before they can be used. Secrets and policies reference environments via dropdown — no free-text entry. This prevents typos and ensures consistency.

On upgrade, existing project/environment pairs from secrets and policies are automatically seeded into the environments table.

## Access Policies

Policies control which GitHub Actions workflows can access which secrets. Each policy specifies:

- **Repository pattern** — glob pattern matching repository names (e.g. `myorg/*`, `myorg/myrepo`)
- **Ref pattern** — glob pattern matching git refs (e.g. `refs/heads/main`, `*`)
- **Project + Environment** — which secrets the policy grants access to (selected from managed environments)

When a GitHub Actions workflow requests secrets, the server:
1. Validates the OIDC token
2. Finds policies matching the token's repository and ref claims
3. Returns secrets from matching project/environment pairs

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
