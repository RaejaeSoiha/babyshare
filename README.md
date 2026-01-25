# Free File Share with QR Code

A LAN/online file sharing app with QR codes, encryption, and guest access.

## Stack
- Backend: Node.js + Express
- Frontend: React + TypeScript (Vite)

## Setup

Install backend dependencies:
```bash
npm install
```

Install frontend dependencies:
```bash
cd client
npm install
cd ..
```

Create `.env` (optional):
```env
PORT=3000
HTTP_PORT=3001
FILE_KEY=your-secret-key
SESSION_SECRET=your-session-secret
DOMAIN=https://your-domain.com
FORCE_HTTPS=false
SHARE_USE_HTTPS=false
```

## Run (development)

Start backend:
```bash
npm run dev
```

Start frontend dev server (separate terminal):
```bash
npm run client:dev
```

## Build (production)

```bash
npm run build
npm start
```

Then open:
- http://localhost:3000
- Or the LAN IP shown in the terminal

## Notes
- The backend still serves login/register/guest endpoints.
- After build, Express serves the React frontend from `client/dist`.
- If `FORCE_HTTPS=true` and you use a self-signed cert, share links default to HTTP on `HTTP_PORT` to avoid mobile/browser SSL errors. Set `SHARE_USE_HTTPS=true` to force HTTPS links.
