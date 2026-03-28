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

## Key packages

- `cmd/server` — entrypoint, route wiring
- `internal/auth` — CF Access JWT + GitHub OIDC validation
- `internal/config` — env var loading
- `internal/crypto` — AES-256 encryption for secret values
- `internal/database` — SQLite via modernc.org/sqlite
- `internal/handlers` — HTTP handlers (admin API, public API, UI)
- `internal/templates` — embedded HTML templates
