# BabyShare

BabyShare is a private, direct device-to-device file-sharing workspace. Files
move through encrypted WebRTC data channels between the sender and recipient;
BabyShare never accepts, stores, relays, scans, previews, or downloads file
bytes. The service handles only authentication, consent, presence, pairing
codes, and short-lived WebRTC signaling.

## What is stored

- Account and session records
- Temporary nearby-device presence and WebRTC offer/answer/ICE messages
- Direct-transfer metadata: filename, relative folder path when selected,
  size, peer, time, progress, and status
- An eight-digit QR-pairing lookup that expires after ten minutes

No file content, file URL, upload blob, object key, or server-side download
copy is stored. A completed file is written to the recipient's chosen local
location. Browsers without the File System Access API use a capped 32 MB
in-memory fallback; larger receives require the native save-file picker.

## Use the app

1. Create an account and open **Send files** on the sender’s device.
2. Open BabyShare on the receiving device. It appears in **Nearby devices**;
   your own device is not counted.
3. Select files or a folder, select the recipient, and request the transfer.
4. The recipient sees the filename and size, chooses a local save location,
   and accepts or declines.
5. Keep both pages open while the WebRTC transfer completes. Either person can
   cancel; failures remain metadata only and can be retried.

For someone without an account, use **Send with QR pairing**. They can scan the
code or enter the displayed eight-digit pairing code at `/guest-receive`.

## Local development

```bash
npm install
npm --prefix client install
npm run build
npm start
```

For Vite development, run `npm run client:dev`. The Vite proxy is configured in
`client/vite.config.ts`.

## WebRTC networking

BabyShare uses `stun:stun.cloudflare.com:3478` by default. For networks that
block direct peer-to-peer paths, build with a TURN service configuration:

```dotenv
VITE_WEBRTC_TURN_URLS=turn:turn.example.com:3478?transport=udp
VITE_WEBRTC_TURN_USERNAME=short-lived-username
VITE_WEBRTC_TURN_CREDENTIAL=short-lived-credential
```

Vite variables are part of the browser build, so use time-limited TURN
credentials. TURN relays packets in transit when necessary; it is not
BabyShare file storage.

## Cloudflare Workers

The Cloudflare Worker uses D1 for accounts/sessions and Durable Objects for
ephemeral presence and signaling. It has no R2 binding and no upload endpoint.

```bash
npx wrangler login
npx wrangler d1 create babyshare
# Copy the resulting database_id into wrangler.toml.
npm run cf:d1:migrate
npx wrangler secret put SESSION_SECRET
npx wrangler secret put LAN_SCOPE_SECRET
npx wrangler secret put BOOTSTRAP_ADMIN_PASSWORD
npm run cf:deploy
```

`BOOTSTRAP_ADMIN_USERNAME` defaults to `admin`. After first sign-in, remove the
bootstrap password secret if you do not need recovery:

```bash
npx wrangler secret delete BOOTSTRAP_ADMIN_PASSWORD
```

When deploying from the Cloudflare Git build screen, use this deploy command so
the QR pairing-code table is migrated before the Worker is published:

```bash
npm run cf:d1:migrate && npx wrangler deploy
```

The Worker also creates the small pairing-code metadata table lazily as a safe
fallback, but migrations remain the expected production deployment path.

## Security model

- Same-origin request checks and secure, `HttpOnly` session cookies protect
  account actions.
- Browser device IDs use random, locally stored credentials; only the same
  BabyShare scope can list or signal a device.
- File transfers require explicit recipient approval.
- Signaling queues are capped and expire quickly. Chat messages are removed
  when either participant ends the conversation.
- There is no fallback HTTP upload, encrypted relay file, file vault, preview,
  or server download endpoint.

## Verify

```bash
npm test
npm run client:build
npm run cf:dry-run
npm run check:production-config
```

The integration suite verifies session continuity, blocks authenticated and
guest HTTP upload bodies, verifies recipient-approved direct-transfer metadata,
and confirms signaling is metadata only.
