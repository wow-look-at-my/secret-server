# secret-server

Self-hosted secrets manager. Single Go binary, SQLite storage, two auth zones.

## Build & Test

```bash
go-toolchain
```

This runs mod tidy, vet, tests with coverage, and builds. Do not use bare `go` commands.

## Architecture

Two path prefixes for Cloudflare Access:

- `/admin/*` — protected (API + web UI)
- `/github/*` — bypassed (GitHub Actions OIDC)
- `/health` — not routed through CF Access (Docker/uptime checks)

Route constants are in `internal/handlers/routes.go`. Templates use `{{prefix}}` to
reference the admin UI prefix.

- **Encryption at rest**: Secrets are AES-256-GCM encrypted in SQLite, base64-encoded. Decrypted only in memory on retrieval.
- **Managed environments**: Project/environment pairs are first-class entities with UUID primary keys. Secrets and policies reference them by `environment_id` (FK), not by string tuple. Environments can be renamed without updating referencing rows. Auto-migrated from legacy string-column schema on upgrade.
- **Policy-based access**: Glob patterns on repository name + git ref determine which secrets a workflow can access.
- **Pure-Go SQLite**: Uses `modernc.org/sqlite` (no CGO required). CGO is disabled in the build.

## Key packages

- `cmd/server` — entrypoint, chi router wiring, gorilla/csrf middleware
- `internal/auth` — CF Access JWT + GitHub OIDC validation
- `internal/config` — env var loading (derives CSRF key from ENCRYPTION_KEY via HKDF)
- `internal/crypto` — AES-256 encryption for secret values
- `internal/database` — SQLite via modernc.org/sqlite
- `internal/handlers` — HTTP handlers (admin API, public API, UI); Register methods accept chi.Router
- `internal/templates` — embedded HTML templates (CSRF token via gorilla/csrf)

## Configuration

All via environment variables. Required: `ENCRYPTION_KEY`, `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_ADMIN_AUDIENCE`. See README.md for full table.

## CI

Downloads `go-toolchain` binary in CI and runs it. Triggered on every push. No PRs merge without passing CI.
