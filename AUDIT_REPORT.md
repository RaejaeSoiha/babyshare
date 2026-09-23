# BabyShare Pre-Deployment Audit (Baseline)

Date: 2026-09-23

This report records the codebase state before production-readiness changes. No
user uploads, JSON data stores, or databases were deleted during this audit.

## Scope

- Node/Express service in `src/`
- React/Vite client in `client/`
- Docker, Nginx, shell, and Tauri packaging configuration
- Git-tracked state, generated output, and repository hygiene

## Release-blocking findings

1. `certs/selfsigned.key` is tracked in Git. A private TLS key must never be
   versioned; the committed key must be considered exposed and replaced.
2. `users.json`, `shares.json`, and `guestFiles.json` are tracked application
   state. This risks publishing account hashes, sharing metadata, and data
   references with source control.
3. The server permits a fallback session secret and encryption key, and creates
   a default `admin`/`admin123` account when no store is present. Production
   startup must reject this configuration.
4. `/download/:u/:f` only required a login, allowing any logged-in user to
   request another user's known file path (IDOR).
5. User share expiry was not checked when serving `/secure-download`; cleanup
   ran hourly, leaving an expiry window in which a link remained usable.
6. Password-protected signed-in shares render action links without a password
   form, so the documented password flow cannot complete in the browser.
7. Guest uploads had no size, field-count, or file-count limits. Both upload
   paths accepted arbitrary files without filename validation.
8. Usernames were unvalidated before being used as directory names, enabling
   path traversal through registration or user management.
9. Authenticated state-changing operations included GET deletion/logout and
   lacked an origin/CSRF defense. Admin password reset defaulted to a public,
   predictable password.
10. Sessions used Express's in-memory store, created sessions for anonymous
    visitors, lacked hardened cookie settings, and have no production session
    secret requirement.
11. New uploads use AES-CTR, which provides confidentiality but no tamper
    detection. Legacy files need compatibility-preserving handling.

## Important non-blocking findings

- The frontend references `/logo.svg`, but the file is deleted in the active
  worktree, producing a missing favicon.
- UI copy contains mojibake characters and the home preview has nonfunctional
  buttons. Upload views have no byte-level progress feedback.
- The client imports remote Google fonts at runtime; it will fail closed to
  fallbacks on isolated LAN deployments.
- Production configuration uses `npm install --production` rather than a
  deterministic lockfile install, exposes the Docker socket to nginx-proxy,
  and maps only port 3000 while share-link code may choose port 3001.
- The active frontend uses `react-router-dom` v7 APIs compatible with its
  usage, but contains a legacy `Navigate` route for a backend endpoint that
  needs to remain server protected.
- `archiver`, `ejs`, and `node-cron` are declared but currently unused by
  runtime source. They should be removed only after verification.
- `client/package/`, `client/caniuse-lite-*.tgz`, duplicate `src-tauri/` trees,
  and Tauri `target/` build output appear to be generated or duplicate
  artifacts. They are untracked and will not be deleted automatically because
  desktop packaging ownership has not been established.
- `views/guest-success.ejs`, `guestFiles.json`, `strcture.txt`, and several
  operational shell scripts are not referenced by runtime code. They are
  retained pending explicit archival/deletion confirmation.

## Planned remediation

1. Add configuration validation, secure sessions, request limits, rate limits,
   authentication/authorization checks, expiry checks, and safe path handling.
2. Preserve old encrypted files while writing authenticated AES-GCM encryption
   for new uploads.
3. Repair signed-in password access, deletion semantics, upload errors and
   progress, favicon/brand consistency, responsive states, and API errors.
4. Add targeted integration tests for authorization, expiry, protected shares,
   and upload limits; then run lint, typecheck, production builds, dependency
   audits, and security checks.

## Deliberately preserved during audit

- `uploads/` and all encrypted user/guest files
- Current `users.json` and `shares.json` data
- Existing uncommitted worktree modifications
- Tauri/package artifacts until their active packaging path is verified
