# Security Policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability
reporting](https://github.com/wow-look-at-my/secret-server/security/advisories/new)
— the **Security** tab of this repository, "Report a vulnerability". Please do
not open a public issue for a security problem.

Include what you can: affected version or commit, the request or configuration
that reproduces it, and what an attacker gains. Never include real secret
values, tokens, or encryption keys in a report.

This is a homelab project maintained on a best-effort basis. There is no
support contract and no guaranteed response time.

## Supported versions

Only the current `master` branch is supported. Fixes land there; there are no
backports to older tags or images.

## What this project treats as a vulnerability

The security model is that the only route reachable without Cloudflare Access
is `GET /github/v1/secrets` (plus `HEAD/POST /github/v1/push-provenance`,
`/health`, and `/llms.txt`), and that route vends **only** the secrets a
presented credential is authorized for. Reports in scope include:

- Vending a secret to a credential that no matching policy or attachment grants.
- Bypassing OIDC or machine-token validation, or forging either credential.
- Reading or writing the secret tree, policies, or machine tokens without a
  valid Cloudflare Access JWT.
- Recovering plaintext secrets from the database file, a log line, an error
  message, or the audit log.
- Recording push provenance without the `can_attest_github_pushes` capability,
  or attesting a ref that GitHub did not report as updated.

Out of scope: anything that requires the `ENCRYPTION_KEY`, an admin session, a
machine token, or filesystem access on the host — those are trusted inputs by
design. Missing hardening headers on the Cloudflare-Access-protected admin UI
are also out of scope.

## Operator responsibilities

The threat model assumes the deployment does these; none is enforced by the
binary:

- `ENCRYPTION_KEY` is 32 random bytes, kept out of the repository and out of
  the shell history, and backed up — losing it makes every stored secret
  unrecoverable.
- Cloudflare Access protects `/admin/*`, with bypasses only for `/github/*`,
  `/health`, and `/llms.txt`.
- The server is reached over HTTPS. It speaks plain HTTP and expects a TLS
  terminator in front of it.
- The database files and their backups are treated as ciphertext worth
  protecting: an attacker holding both a database file and the encryption key
  holds every secret.
- Machine tokens with `can_attest_github_pushes` never enter a job, hook, or
  agent container.
