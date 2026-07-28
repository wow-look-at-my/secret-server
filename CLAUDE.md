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
- `/llms.txt` — public plain-text guide for LLMs/agents (llmstxt.org convention; `internal/handlers/llms.go`, embedded `llms.txt` with per-request `{{BASE_URL}}` substitution). CF Access needs a path bypass for `/llms.txt` (like `/github/*`) for it to be publicly reachable.

Route constants are in `internal/handlers/routes.go`. Templates use `{{prefix}}` to
reference the admin UI prefix.

- **Encryption at rest**: Secrets are AES-256-GCM encrypted in SQLite, base64-encoded. Decrypted only in memory on retrieval.
- **Composite secret tree**: Secrets live in a `secret_nodes` table as either `secret` leaves or `group` composites, forming an arbitrary-depth tree. The `ISecretNode` interface exposes uniform `ID() / Name() / ParentID() / Children()` methods — a leaf's `Children()` returns nil so tree walks don't need type switches. Secret names are **globally unique** across the whole server (partial unique index); group names are unique within their parent. The global-uniqueness invariant is what lets the public API return `{name: value}` without collision handling.
- **Policy-based access**: Each policy is a pure pattern-match rule with normalized `policy_patterns(policy_id, kind, pattern)` rows for the three kinds (`repository`, `ref`, `actor`). Repository, ref, SHA, OIDC actor login, and OIDC actor ID come from the GitHub-signed Actions token. If an exact repository/ref/SHA has Agent Host push provenance, policy matching uses that attested human login and immutable ID instead, while audit details retain both identities and the source. Actor patterns match either the login or explicit `id:<numeric ID>`. Tokens missing any required claim fail closed. A request matches a policy iff one pattern of each kind matches via SQLite's native `GLOB` operator — matching runs entirely inside SQLite, no Go-side loops or JSON parsing. A policy with zero patterns of a kind matches nothing for that kind (no implicit wildcard; write `*` explicitly) — and the admin form and `policyRequest.normalize` honor this: all three kinds are left **blank by default** (the old "empty ref/actor → `["*"]`" injection is gone), so a new policy is fail-closed and a blank ref/actor can never silently widen it to any-ref/any-actor. Each pattern is bracket-escaped before matching (`replace(pattern,'[','[[]')` in `matchingPolicyIDsSQL`): SQLite GLOB reads `[...]` as a character class and has no escape, so without this an actor pattern with literal brackets — bot logins like `pr-minder[bot]` / `dependabot[bot]` — could never match its own value (and silently over-matched the class expansion, e.g. `pr-minderb`). Escaping makes brackets literal; `*`/`?` wildcards and bracket-free patterns are unchanged.
- **Machine tokens**: bearer credentials (`sst_<random>`, SHA-256–hashed at rest) for clients that can't present a GitHub OIDC JWT (e.g. webhook-runner hooks). A token grants secrets **two ways, either or both**: by attaching **directly to secret-tree nodes** (`machine_token_nodes` junction) and/or via an **optional bound policy** (the nullable `machine_tokens.policy_id`). Separately, the default-off `can_attest_github_pushes` capability permits the Agent Host control plane to call `HEAD/POST /github/v1/push-provenance`; secret grants never imply that authority, and such a token must never enter a job or agent container. `fetchSecretsMachine` (public.go) vends `AuthorizedSecretsForToken`, the same downward-walk CTE as the OIDC path but seeded from **both** the token's direct attachments and its policy's attached nodes (attaching/binding a **group** grants its whole subtree). Direct attachment is the no-busywork default; a policy is for a reusable grant shared across tokens. Both credential types share `GET /github/v1/secrets` (the `database.MachineTokenPrefix` on the bearer token selects the path — no extra CF bypass). Admin REST create/update accept `{name, policy_id?, node_ids?, can_attest_github_pushes?}` and the UI exposes the capability with a high-trust warning. Ordinary grant updates preserve it; admin updates change grants and capability atomically. Plaintext is shown once, at creation or regeneration. Existing tokens migrate with attestation disabled.
- **Agent Host provenance**: Agent Host preflights before forwarding a commit push, parses Git receive-pack report-status, and posts only successfully updated heads/tags with exact repository/ref/SHA plus the OAuth user's login and immutable numeric ID. The primary key is `(repository, ref, sha)`. Actions resolution requires an exact match; missing provenance falls back to the signed OIDC actor. The attestation audit entry and subsequent secret-access entry preserve the OIDC actor, resolved human, identity source, and machine-token ID without logging either credential.
- **Attach + precedence**: Policies are attached to nodes via the unordered-set `secret_node_policies` junction table. A policy attached to a group grants access to every descendant leaf (inheritance via a recursive CTE in the public API hot path). Optional `policy_precedence` rows describe directed "A must evaluate before B" edges per node; `DB.ListNodePolicies` returns the attached set in topological order via a Kahn's-algorithm sort, tie-broken by name. Cycle detection runs in Go (DFS) at insert time because SQLite can't enforce it without triggers. Matching is still pure OR — precedence only affects UI display and any future override/deny resolver.
- **Legacy migration**: On upgrade from the old `environments`/`secrets`/`access_policies` schema, every old secret is flattened into a single root-level leaf with name `<project>-<environment>-<key>` (prefix required to satisfy global uniqueness). No groups are created; the admin reorganizes the tree after upgrade. Policies are preserved with patterns normalized into `policy_patterns`, but attachments are NOT carried over and legacy empty-list-as-wildcard is NOT synthesized — the admin re-attaches and fixes any relying policies as a conscious authorization review.
- **Pure-Go SQLite**: Uses `modernc.org/sqlite` (no CGO required). CGO is disabled in the build.
- **sqlc codegen**: SQL queries live in `internal/database/sqlc/queries/*.sql`. Run `sqlc generate` to regenerate Go code after modifying queries. Never edit files in `internal/database/sqlc/` directly. Exception: `MatchingPolicyIDs` is hand-rolled raw SQL in `internal/database/policies.go` because sqlc v1.28.0 has an off-by-N bug that truncates the tail of generated query strings containing SQLite `?` placeholders.

## Key packages

- `cmd/server` — entrypoint, chi router wiring, gorilla/csrf middleware
- `internal/auth` — CF Access JWT + GitHub OIDC validation
- `internal/config` — env var loading (derives CSRF key from ENCRYPTION_KEY via HKDF)
- `internal/crypto` — AES-256 encryption for secret values
- `internal/database` — SQLite via modernc.org/sqlite; queries generated by sqlc
- `internal/database/sqlc` — sqlc-generated type-safe query code (DO NOT EDIT); regenerate with `sqlc generate`
- `internal/handlers` — HTTP handlers (admin API, public API, UI); Register methods accept chi.Router
- `internal/templates` — embedded HTML templates (CSRF token via gorilla/csrf)

## Configuration

All via environment variables. Required: `ENCRYPTION_KEY`, `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_ADMIN_AUDIENCE`. See README.md for full table.

## CI

Downloads `go-toolchain` binary in CI and runs it. Triggered on every push. No PRs merge without passing CI.
