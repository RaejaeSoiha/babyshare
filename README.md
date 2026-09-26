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

Development can use its local fallback keys for compatibility with an existing
local data store. They are intentionally rejected when `NODE_ENV=production`.

## Production configuration

Copy `.env.example` to `.env` outside source control and set unique secrets.
`SESSION_SECRET` and `FILE_KEY` must each be at least 32 characters. `FILE_KEY`
must be retained for as long as any uploaded files need to be read; rotating it
without a deliberate re-encryption migration makes existing uploads unreadable.

Set `PUBLIC_BASE_URL` to the external HTTPS URL used by recipients. Place
BabyShare behind a TLS-terminating reverse proxy, set `TRUST_PROXY=true`, and
forward `X-Forwarded-Proto`. Do not use the bundled self-signed development
certificate in production.

The container configuration binds the current `uploads/`, `users.json`, and
`shares.json` into `/data`; it does not bake them into the image or delete them.
Back up those paths and the `FILE_KEY` together. Provision a production
administrator in `users.json` before the first production start.

```bash
docker compose build
docker compose up -d
```

The Compose port is loopback-only (`127.0.0.1:3000`) so the reverse proxy is the
only public entry point.

## Checks

```bash
npm test
npm --prefix client run lint
npm run build
npm audit --omit=dev
```

## Nearby Devices and direct transfers

BabyShare discovers active browser devices connected to the same BabyShare LAN
hub without requiring either person to log in. Open the hub's LAN URL on
Windows, macOS, Linux, Android, or iOS; a device appears in **Nearby Devices**
while its BabyShare page is open. Before files can be selected, one person starts
secure verification and both people compare the same two-digit code by phone or
in person, then each confirms that it matches. This protects against choosing
the wrong nearby device without creating a contact list or durable history.

After both people confirm the code, the sender can choose up to 20 files. The
verification is consumed as soon as a transfer request is created, so a fresh
code is required for the next direct transfer. The recipient receives an in-app
notification and must explicitly accept or decline each transfer.

The sender's browser retains the selected files until they are accepted, then
uploads them to the hub with live progress visible to both browsers. Keep the
sender page open until the transfer reaches **Ready to download**. Received files are
available only from the in-app notification, are not given public links, and are
deleted from BabyShare's encrypted transfer storage immediately after a successful
download. A received transfer can be downloaded once.

After verification, either person can request a private chat; the other person
must accept it. Chat messages exist only while that chat is active and only in
server memory. When either person selects **End chat**, the entire conversation
is deleted immediately for both devices. Declined chat requests are also deleted
immediately, and inactive chats expire automatically after 30 minutes. Device presence,
verification codes, and transfer metadata are likewise memory-only. Declined
verification and transfer requests are deleted immediately; verification codes
expire after five minutes; and a successful one-time download deletes both the
encrypted temporary file and its transfer record.

The Node host emits low-TTL LAN multicast service announcements on
`239.255.77.77:42424` to aid hub discovery on networks that permit multicast.
Browsers cannot send UDP/mDNS packets, so the presence API is the compatible
fallback used by desktop and mobile browsers. If multicast is blocked by guest
Wi-Fi, a VPN, or a mobile hotspot, open the known BabyShare LAN URL directly on
each device; Nearby Devices still works normally once they are on that hub.

### LAN transfer security

- LAN transfer routes reject non-private source addresses. They accept only
  loopback, RFC1918 IPv4, IPv6 unique-local, or IPv6 link-local traffic.
- Each browser device has a locally stored random device credential. The server
  scopes devices to the local subnet and requires that credential for listing,
  accepting, uploading, or downloading a private transfer.
- Both people must confirm the same temporary code before a transfer request is
  allowed. The code is scoped to the two current LAN devices, expires after five
  minutes, and is deleted when used or declined.
- Private chat requests use the same verified device pair. Either person can
  end a chat, immediately removing its messages from the server and both UIs.
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
