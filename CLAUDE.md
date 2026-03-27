# CLAUDE.md

## Project overview

Self-hosted secrets manager for homelab GitHub Actions. Single Go binary, SQLite storage, two auth zones (GitHub OIDC for public API, Cloudflare Access for admin).

## Build and test

```bash
go-toolchain
```

This handles mod tidy, testing, coverage, and building. Do NOT use `go build`, `go test`, or other bare `go` commands directly.

## Project structure

```
cmd/server/          Entry point (main.go)
internal/
  auth/              GitHub OIDC + Cloudflare Access JWT validation
  config/            Configuration loading from env vars
  crypto/            AES-256-GCM encryption/decryption
  database/          SQLite layer (secrets, policies, glob matching)
  handlers/          HTTP handlers (public API, admin API, web UI)
  templates/         HTML templates for web UI
action.yml           GitHub Action composite (fetch secrets in workflows)
docker-compose.yml   Multi-stage Docker build + deployment
```

## Key architecture decisions

- **Two auth zones**: Public API uses GitHub OIDC tokens validated against GitHub's JWKS. Admin routes use Cloudflare Access JWTs.
- **Encryption at rest**: Secrets are AES-256-GCM encrypted in SQLite, base64-encoded. Decrypted only in memory on retrieval.
- **Policy-based access**: Glob patterns on repository name + git ref determine which secrets a workflow can access.
- **Pure-Go SQLite**: Uses `modernc.org/sqlite` (no CGO required). CGO is disabled in the build.

## Configuration

All via environment variables. Required: `ENCRYPTION_KEY`, `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUDIENCE`. See README.md for full table.

## CI

Uses `wow-look-at-my/go-toolchain@v1` GitHub Action. Triggered on every push. No PRs merge without passing CI.
