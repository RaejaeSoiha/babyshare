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

## Security notes

- New uploads use versioned AES-256-GCM encryption. Existing AES-CTR uploads
  remain readable for compatibility but should be re-uploaded if integrity
  verification is required.
- File previews are limited to a conservative set of media, PDF, and plain-text
  types. Other files download as attachments.
- Password and login attempts are rate-limited in process. Use a shared edge
  limiter when running more than one application instance.
