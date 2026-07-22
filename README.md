# secret-server

Self-hosted secrets manager for homelab use. Single Go binary with SQLite storage, two auth zones, and a web UI.

## Architecture

| Zone | Routes | Auth | Access |
|------|--------|------|--------|
| GitHub API | `GET /github/v1/secrets` | GitHub Actions OIDC JWT **or** machine token | Read-only — vend authorized secrets |
| Admin API | `/admin/v1/*` | Cloudflare Access JWT | Manage the secret tree, policies, attachments, and machine tokens |
| Admin UI | `/admin/*` | Cloudflare Access JWT | Web UI for the secret tree, policies, attachments, and machine tokens |

Two path prefixes for Cloudflare Access: protect `/admin/*`, bypass `/github/*`. The GitHub API validates OIDC tokens directly. Admin routes are protected by Cloudflare Access (the server validates CF JWTs as defense-in-depth). The root path `/` redirects to the admin UI. `GET /health` is available for Docker/uptime checks (not routed through CF Access). `GET /llms.txt` serves a plain-text guide to the server for LLMs/agents ([llms.txt](https://llmstxt.org) convention) — public, but the Cloudflare Access application needs a path bypass for `/llms.txt` (like `/github/*`) for it to be reachable.

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
- **Node management** — create, update, delete of secret-tree nodes (both groups and secrets) by admin users
- **Policy management** — create, update, delete of access policies and their attachments by admin users

The audit log is isolated from the main database to prevent corruption of credential data during hardware or power failures. View the audit log at `/admin/audit`.

## The Secret Tree

Secrets are organized as a tree of **nodes**. A node is either:

- **Secret** — a leaf holding one encrypted key/value. Secret names are **globally unique across the whole server**, so the public API can return `{name: value}` with no risk of collision between leaves in different subtrees. Prefix names with the owning app (e.g. `myapp-DATABASE_URL`) to avoid naming conflicts.
- **Group** — a composite holding zero or more child nodes. Group names are unique only within their parent, so multiple groups named `prod` may exist under different parents. Arbitrary nesting depth is supported.

Groups exist purely to organize secrets and to attach policies that inherit down the subtree. There is no inherent project/environment concept — you pick whatever grouping makes sense for your setup.

## Access Policies

Policies are pure pattern-match rules that you **attach** to one or more nodes. Each policy specifies:

- **Repository patterns** — zero or more SQLite GLOB patterns matching repository names (e.g. `myorg/*`, `myorg/api-*`). A request matches if the repository matches **any** of the listed globs. Leaving this empty is allowed: the policy then has no repository patterns and matches nothing (see below), so you can create a placeholder policy now and add patterns later without granting any access in the meantime.
- **Ref patterns** — one or more SQLite GLOB patterns matching git refs (e.g. `refs/heads/main`, `refs/tags/v*`). At least one is required (`*` for "any ref"). In the UI, leaving the field blank defaults to `*`.
- **Actor patterns** — one or more SQLite GLOB patterns matching the GitHub username that triggered the workflow (e.g. `deploy-*`). At least one is required (`*` for "any actor"). In the UI, leaving the field blank defaults to `*`.

A policy with zero patterns of any kind matches nothing — there is no implicit "empty = wildcard" behavior. This is fail-closed: an empty (or partially-filled) policy never grants access, which is what makes it safe to save an incomplete policy and finish it later. Patterns are stored as normalized rows in `policy_patterns(policy_id, kind, pattern)` so matching runs entirely inside SQLite via the native `GLOB` operator.

When a GitHub Actions workflow requests secrets, the server:

1. Validates the OIDC token.
2. Finds every policy whose pattern rows all match the token's repository, ref, and actor claims (single SQL query via `GLOB` joins).
3. Walks the secret tree via a recursive CTE to collect every leaf that is either directly attached to a matching policy or inherited from an ancestor that is.
4. Decrypts the values and returns them as `{name: value}`.

A policy attached to a group grants access to **every descendant leaf** of that group. Inheritance is additive — a leaf is accessible as long as at least one matching policy is attached on the leaf itself or any of its ancestors.

Policies can optionally have **precedence edges** per node — directed "policy A must be evaluated before policy B" constraints. These only affect the display order in the admin UI (and any future override/deny resolver); they don't change which secrets are returned to the GitHub Actions caller.

### Legacy migration

On upgrade from an older schema that used `environments`/`secrets`/`access_policies` tables, the server automatically flattens every old secret into a single root-level leaf with name `<project>-<environment>-<key>`. No groups are created; you reorganize the flat list into a tree after upgrade. Existing policies are preserved with their patterns normalized into `policy_patterns`, but **attachments are not carried over** and legacy empty-list-as-wildcard is not synthesized — this is deliberate, to force a conscious re-review of authorization on the new model. Unattached nodes show a "no policies" indicator in the admin UI so the unauthorized state is obvious at a glance.

## Machine Tokens

GitHub Actions OIDC is the right credential for a workflow, but some clients can't present an OIDC token — e.g. a [webhook-runner](https://github.com/wow-look-at-my/webhook-runner) hook running in a plain Docker container. **Machine tokens** fill that gap: a long-lived bearer credential that grants a chosen set of secrets, presented to the *same* `GET /github/v1/secrets` endpoint.

- **Shape:** `sst_<random>`. The server inspects the bearer token — the `sst_` prefix routes it to machine-token validation; anything else is validated as an OIDC JWT. Both share one route, so there is no extra Cloudflare Access bypass path to configure.
- **Storage:** only the token's SHA-256 hash is stored. The plaintext is shown **once**, at creation or regeneration, and cannot be recovered — lose it and you regenerate (a fresh value in place) or revoke + reissue.
- **Access — direct, a policy, or both:** a machine token grants secrets by attaching **directly to secret-tree nodes** (pick the exact secrets, or a group to grant its whole subtree) **and/or** by binding an **optional policy** (a reusable grant you can share across tokens). It vends the **union** of the two, using the same downward-walk resolution as the OIDC path. Direct attachment is the simple default — no policy and no repo/ref/actor patterns required; the policy's patterns are never consulted for a machine token. Deleting a secret cascades its attachment away; deleting a bound policy just unbinds it (the token survives).
- **Management:** create, list (by name + prefix, showing the granted secrets and bound policy), edit (change the secrets and/or policy), regenerate (mint a fresh token value in place — same name, policy, and attachments; the old value stops working immediately), and revoke on the **Machine Tokens** admin page, or via `GET/POST/PUT/DELETE /admin/v1/machine-tokens` plus `POST /admin/v1/machine-tokens/{id}/regenerate` (create/update take `{name, policy_id?, node_ids?}`; create and regenerate return `{id, token}` — the only times the token is exposed).
- **Audit:** every machine-token vend is recorded as `secret.access.granted` with actor type `machine_token`; denied attempts (unknown/revoked token) as `secret.access.denied`.

```bash
curl -fsSL -H "Authorization: Bearer $SECRET_SERVER_TOKEN" \
  https://secrets.example.com/github/v1/secrets
# {"GITHUB_APP_PRIVATE_KEY":"-----BEGIN ...","AI_API_KEY":"..."}
```

## Cloudflare Access Setup

1. Create a self-hosted application in Cloudflare Access
2. Set the application URL to cover `/admin/*` (covers both the API and web UI)
3. Add bypass rules for `/github/*` (the OIDC API), `/health`, and `/llms.txt`
4. Configure the `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_ADMIN_AUDIENCE` env vars

## Dependencies

| Package | License | Purpose |
|---------|---------|---------|
| [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) | BSD-3-Clause | Pure-Go SQLite driver |
| [github.com/google/uuid](https://pkg.go.dev/github.com/google/uuid) | BSD-3-Clause | UUID generation |
| [github.com/go-jose/go-jose/v4](https://pkg.go.dev/github.com/go-jose/go-jose/v4) | Apache-2.0 | JWT/JWKS validation |

All other functionality uses the Go standard library.
