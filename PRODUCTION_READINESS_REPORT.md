# BabyShare Production Readiness Report

Date: 2026-09-23

## Status

**Not ready to deploy yet.** The code and production dependency set pass the
available checks, but the current local environment does not provide strong
production secrets or an HTTPS public URL. Deployment is intentionally blocked
by startup validation until those values are supplied.

## Issues discovered and fixed

- Fixed an IDOR in authenticated downloads: users can now download only their
  own files, while administrators retain administrative access.
- Enforced signed-in and guest share expiry during every request, not just the
  hourly cleanup pass.
- Repaired the password-protected signed-in share flow by rendering an actual
  password form and validating it before download or preview.
- Added safe path containment, username validation, opaque UUID filenames for
  new user uploads, and validated upload filenames/metadata.
- Applied file-count, part-count, field-size, and 1 GB per-file limits to both
  upload paths. The client now shows byte-level upload progress and helpful
  limit errors.
- Replaced state-changing GET deletion/logout with POST/DELETE flows and added
  same-origin checks for state-changing requests.
- Added in-process limits for login, upload, and shared-password attempts.
- Replaced anonymous in-memory sessions with a file-backed session store,
  hardened cookie settings, disabled anonymous session creation, and saved a
  regenerated login session before redirecting.
- New uploads use versioned AES-256-GCM encryption with integrity verification.
  Existing AES-CTR files remain readable so no user-uploaded data was changed.
- Removed public Host-header reflection from generated share URLs. Production
  links now require the configured `PUBLIC_BASE_URL`.
- Removed runtime Google-font dependency, repaired the missing favicon, fixed
  mojibake text, nonfunctional preview controls, and loading/error/empty UI
  states.
- Updated Express to 5.2.1 and Multer to 2.4.0. The production dependency audit
  now reports zero vulnerabilities.
- Added production startup validation, a multi-stage container image, health
  check, runtime data mounts, `.dockerignore`, `.env.example`, and deployment
  documentation.
- Hardened the active Tauri sidecar path: release builds now use a persisted
  per-user secret store and a non-null content security policy.

## Cleanup completed

- Removed unused runtime dependencies: `archiver`, `ejs`, and `node-cron`.
- Removed direct `caniuse-lite` dependency from the client; it remains only as
  a build-tool transitive dependency where required.
- Added ignore rules for runtime data, keys, sessions, package artifacts, and
  Tauri build output.
- Removed `certs/selfsigned.key`, `users.json`, `shares.json`, and
  `guestFiles.json` from Git tracking only. Their local working copies remain
  intact; no uploaded files or data stores were deleted.

## Test results

- `npm test`: pass (4 integration tests).
- `npm --prefix client run lint`: pass.
- `npm --prefix client run build`: pass.
- JavaScript syntax checks: pass.
- `npm audit --omit=dev`: 0 vulnerabilities.
- `docker compose config --quiet`: pass.
- Production configuration negative test: pass; startup rejects missing or weak
  `SESSION_SECRET`, `FILE_KEY`, and `PUBLIC_BASE_URL`.
- Desktop configuration test: pass; per-user desktop secret store is created.

## Remaining deployment requirements

1. Provision a 32+ character `SESSION_SECRET`, preserve the existing `FILE_KEY`
   if current encrypted uploads must remain readable, and configure an HTTPS
   `PUBLIC_BASE_URL`. Do not replace `FILE_KEY` without re-encrypting or
   re-uploading existing files.
2. Replace the committed self-signed TLS key with a new externally managed
   certificate/key. The old key is considered exposed even though it is now
   untracked.
3. Put the container behind an HTTPS reverse proxy, set `TRUST_PROXY=true`, and
   back up `uploads/`, `users.json`, `shares.json`, session data, and `FILE_KEY`
   together.
4. Re-upload or migrate legacy AES-CTR files when authenticated integrity is
   required. They remain supported for compatibility but cannot be
   cryptographically authenticated.
5. For multi-instance deployment, replace the file-backed rate/session stores
   with shared infrastructure and add edge rate limiting.

## Verification gaps

- Docker image build was not run because Docker Desktop's Linux engine is not
  running on this machine. Compose configuration validation did pass.
- Tauri Rust compilation was not run because `cargo` is not installed. The
  source/configuration changes were reviewed and the Node-side desktop secret
  path was exercised.
- No browser automation runner is installed, so responsive visual QA was
  validated through the production build and component/CSS inspection rather
  than automated viewport screenshots.
