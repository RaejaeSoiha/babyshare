# BabyShare

Encrypted file sharing with authenticated user accounts, time-limited links,
optional link passwords, and guest uploads.

## Local development

```bash
npm install
npm --prefix client install
npm run build
npm start
```

For a separate Vite development server, run `npm run client:dev` and configure
the backend port in `client/vite.config.ts`.

Development can use local fallback encryption keys for compatibility with an
existing local data store. It never creates a default administrator account;
register a local account for normal use, or provide a `users.json` when
administrator access is needed. Fallback keys are intentionally rejected when
`NODE_ENV=production`.

## Production configuration

BabyShare validates its production contract before listening. Copy
`.env.production.example` to `.env` on the deployment host and set every
placeholder. `SESSION_SECRET` and `FILE_KEY` must be distinct, random values of
at least 32 characters. Keep `FILE_KEY` with encrypted-file backups: changing it
without a planned re-encryption migration makes existing uploads unreadable.

The supplied production stack runs BabyShare loopback-only and Caddy as the
single HTTPS entry point. Caddy obtains and renews certificates automatically;
`PUBLIC_HOST` must resolve publicly to the host and ports 80 and 443 must be
reachable for ACME. Never expose BabyShare's port 3000 to the internet.

```bash
cp .env.production.example .env
# set the secrets, hostname, and ACME email in .env
mkdir runtime-data
# create or restore runtime-data/users.json before startup
docker compose -f docker-compose.production.yml up -d --build
curl --fail https://share.example.com/healthz
```

`docker-compose.production.yml` uses Linux host networking intentionally so the
existing low-TTL LAN multicast discovery reaches the physical network. It is not
for Docker Desktop. For Windows or macOS development, retain `docker-compose.yml`
or run `npm start`; for a production LAN deployment use a Linux host (or run the
Node service directly on the LAN host) and keep the host firewall limited to
ports 80/443 plus the local multicast group `239.255.77.77:42424`.

For a separately hosted frontend, set the exact HTTPS frontend URL in
`FRONTEND_BASE_URL`, build it with `client/.env.production.example` as its
template, and set `VITE_API_BASE` to the API's HTTPS origin. The backend returns
credentialed CORS headers only for `FRONTEND_BASE_URL` and `PUBLIC_BASE_URL`; it
rejects other state-changing origins. A cross-origin frontend uses secure
`SameSite=None` session cookies and therefore requires HTTPS plus either Caddy
(`TRUST_PROXY=true`) or BabyShare's own TLS mode.

Back up `runtime-data/` and `FILE_KEY` together. A production startup refuses to
create a default account, so restore a valid `users.json` or provision an
administrator before the first start.

## Cloudflare Workers deployment

BabyShare includes a separate Cloudflare Worker runtime in
`cloudflare/worker.mjs`. It serves the built React application from Workers
Static Assets and does not load Express, `session-file-store`, Multer, or any
local files. The existing Node runtime is unchanged: `npm start` remains the
correct command for a private LAN hub and its local data directory.

The Worker stores accounts, sessions, and link metadata in D1; file bytes in
R2; and short-lived nearby presence, chat, WebRTC signals, and relay transfer
state in a Durable Object. R2 encrypts stored objects at rest, while the local
runtime continues using its existing application-level AES encrypted files.

### One-time Cloudflare setup

1. Sign in with `npx wrangler login`.
2. Create a D1 database: `npx wrangler d1 create babyshare`. Copy the returned
   database ID into `wrangler.toml`, replacing the all-zero `database_id`.
3. Create the R2 bucket named in `wrangler.toml`:
   `npx wrangler r2 bucket create babyshare-files`. You may choose another
   bucket name, but update `wrangler.toml` to match it.
4. Apply the database schema: `npm run cf:d1:migrate`.
5. Set these Worker secrets, each with a distinct random value of at least 32
   characters except the bootstrap password:

   ```bash
   npx wrangler secret put SESSION_SECRET
   npx wrangler secret put LAN_SCOPE_SECRET
   npx wrangler secret put BOOTSTRAP_ADMIN_PASSWORD
   ```

   `SESSION_SECRET` signs the secure session cookie. `LAN_SCOPE_SECRET` turns
   a Cloudflare-observed network address into an opaque nearby-user scope. The
   bootstrap password creates the `BOOTSTRAP_ADMIN_USERNAME` (default `admin`)
   on the first Worker request. Sign in once, then remove the bootstrap secret
   so it cannot be used again: `npx wrangler secret delete BOOTSTRAP_ADMIN_PASSWORD`.
6. Confirm `CF_MAX_UPLOAD_BYTES` matches your Cloudflare zone upload limit
   before deploying. Free and Pro zones allow 100 MB request bodies, Business
   allows 200 MB, and Enterprise can be configured up to 5 GB. The local app
   retains its 1 GB limit; a Cloudflare zone that accepts less will reject an
   oversized request before the Worker can receive it.

The Durable Object and static-asset binding are declared in `wrangler.toml` and
are provisioned by the first `wrangler deploy`; they do not need separate manual
creation. Keep the Worker on a custom domain or its `workers.dev` address so the
frontend and API share one HTTPS origin.

### Cloudflare commands

```bash
npm run cf:build        # build the frontend for Workers Static Assets
npm run cf:dev          # run the Worker locally with .dev.vars
npm run cf:dry-run      # bundle and validate; never deploys
npm run cf:d1:migrate   # apply D1 migrations to the configured remote database
npm run cf:deploy       # deploy after the resources and secrets above exist
```

Copy `.dev.vars.example` to the ignored `.dev.vars` only for local Worker
development. Existing local `users.json`, `shares.json`, and encrypted upload
files are intentionally not copied to Cloudflare: they require a separate,
planned data migration and the local `FILE_KEY`. Do not point a Cloudflare
deployment at a local data directory.

Cloudflare cannot see a browser's RFC1918 LAN address or send the Node hub's
UDP multicast announcements. In Worker mode, nearby users are scoped to the
same public network egress address; use `npm start` for the existing strict
same-LAN and multicast behavior. Both modes retain recipient approval, direct
WebRTC transfers, the temporary relay fallback, and ephemeral chat semantics.

## Checks

```bash
npm test
npm --prefix client run lint
npm run build
npm audit --omit=dev
docker build --tag babyshare:local .
```

## GitHub Actions and automatic deployment

`.github/workflows/ci.yml` runs the production configuration check, backend
integration tests, frontend lint/build, and a Docker image build for every pull
request and push to `main`.

`.github/workflows/deploy.yml` deploys a validated `main` commit only after a
GitHub **production** environment is configured. It is intentionally disabled
until the repository variable `DEPLOY_ENABLED` is set to `true`, so adding the
workflow cannot accidentally deploy to an unknown host. Set these values in that
environment before enabling it:

| Setting | Type | Purpose |
| --- | --- | --- |
| `DEPLOY_ENABLED=true` | Variable | Enables deployment after CI checks. |
| `DEPLOY_PATH` | Variable | Absolute path to the already-cloned BabyShare repository on the Linux host. |
| `DEPLOY_HOST` | Secret | SSH hostname or address of that host. |
| `DEPLOY_USER` | Secret | Restricted SSH deployment account. |
| `DEPLOY_SSH_KEY` | Secret | Private key for that account. |
| `DEPLOY_KNOWN_HOSTS` | Secret | Pinned `known_hosts` entry; do not use an unverified `ssh-keyscan` in CI. |

The remote host keeps `.env` and `runtime-data/` outside Git. The workflow
fetches the exact `origin/main` revision, rebuilds the production stack, and
requires its loopback health check to pass. Protect the `production` environment
with required reviewers if deployments need an approval gate.

## Nearby Users and direct transfers

BabyShare discovers active browser devices connected to the same BabyShare LAN
hub without requiring either person to log in. Open the hub's LAN URL on
Windows, macOS, Linux, Android, or iOS; a device appears in **Nearby Users**
while its BabyShare page is open. The compact live list shows a signed-in
user's display name and device type, or **Guest** with the device type for an
anonymous session. It exposes no IP addresses. Chat can start immediately: the
recipient must accept it, and either person can end it. A sender can select up
to 20 files and send a direct transfer request immediately; the recipient must
explicitly accept or decline every transfer. This keeps the flow simple without
creating a contact list or durable history.

The sender's browser retains selected files until they are accepted, then sends
them directly to the recipient when a peer connection is available, with live
progress visible to both browsers. Keep both pages open until the recipient
saves the completed file. If the direct connection is unavailable, the sender
uploads through the encrypted one-time relay instead. Received files are never
given public links; relay files are deleted immediately after a successful
download, and direct files are cleared from the receiving browser after saving.

Either nearby device can request a private chat; the other person must accept it.
Chat messages exist only while that chat is active and only in server memory.
When either person selects **End chat**, the entire conversation is deleted
immediately for both devices. Declined chat and transfer requests are deleted
immediately. An active chat remains open while both participants keep their
BabyShare presence alive; device presence and transfer metadata are memory-only.
A successful one-time download
deletes both the encrypted temporary file and its transfer record.

The Node host emits low-TTL LAN multicast service announcements on
`239.255.77.77:42424` to aid hub discovery on networks that permit multicast.
Browsers cannot send UDP/mDNS packets, so the presence API is the compatible
fallback used by desktop and mobile browsers. If multicast is blocked by guest
Wi-Fi, a VPN, or a mobile hotspot, open the known BabyShare LAN URL directly on
each device; Nearby Users still works normally once they are on that hub.

### WebRTC signaling

BabyShare now exposes an opt-out, same-LAN signaling relay at
`/api/lan/signals` for browser WebRTC offer, answer, candidate, and hang-up
messages. It accepts only active device credentials scoped to the same subnet,
queues at most 24 messages for no longer than 60 seconds, and deletes each
message when the recipient reads it. Set `WEBRTC_SIGNALING_ENABLED=false` to
disable these endpoints. When signaling is enabled, an accepted nearby transfer
uses an encrypted WebRTC data channel between the two browsers by default;
BabyShare stores only short-lived transfer metadata and no file bytes. The
receiving browser holds the completed file only until the recipient saves it,
so both people should keep BabyShare open until that step completes. If a direct
channel cannot connect, BabyShare falls back to its existing recipient-approved,
encrypted one-time relay.

For future peer-to-peer WebRTC media or data channels across different networks,
configure a separate TURN service and its credentials in the browser client. A
public signaling URL alone is not a TURN relay and must not be treated as one.

### LAN transfer security

- LAN transfer routes reject non-private source addresses. They accept only
  loopback, RFC1918 IPv4, IPv6 unique-local, or IPv6 link-local traffic.
- Each browser device has a locally stored random device credential. The server
  scopes devices to the local subnet and requires that credential for listing,
  accepting, uploading, or downloading a private transfer.
- Private chats require same-LAN device credentials and recipient acceptance.
  Direct file transfers are recipient-approved. Either person can end a chat,
  immediately removing its messages from the server and both UIs.
- A recipient must accept before a browser is allowed to upload file content.
  Files are encrypted at rest, are never exposed as guest/shareable links, and
  expire automatically after 24 hours if they are not downloaded first.
- Do not expose the BabyShare LAN port through public port forwarding. Use a
  VPN or the existing HTTPS share-link configuration for users outside the LAN.

## Security notes

- New uploads use versioned AES-256-GCM encryption. Existing AES-CTR uploads
  remain readable for compatibility but should be re-uploaded if integrity
  verification is required.
- File previews are limited to a conservative set of media, PDF, and plain-text
  types. Other files download as attachments.
- Password and login attempts are rate-limited in process. Use a shared edge
  limiter when running more than one application instance.
