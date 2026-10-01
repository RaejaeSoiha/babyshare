// Main Express entrypoint: app setup, shared state, routes, and server startup.
const express = require("express");
const session = require("express-session");
const FileStoreFactory = require("session-file-store");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const http = require("http");
const https = require("https");
require("dotenv").config();

const {
  CERT_CRT_PATH,
  CERT_KEY_PATH,
  BIND_HOST,
  DATA_DIR,
  DIST_DIR,
  CROSS_ORIGIN_FRONTEND,
  FRONTEND_BASE_URL,
  HAS_DIST,
  HTTPS_ENABLED,
  HTTP_PORT,
  IS_PRODUCTION,
  LAN_DISCOVERY_PORT,
  LAN_DISCOVERY_PROTOCOL,
  PORT,
  PUBLIC_BASE_URL,
  SHARE_USE_HTTPS,
  SESSION_MAX_AGE_MS,
  TRUST_PROXY,
  validateRuntimeConfig,
  WEBRTC_SIGNALING_ENABLED,
} = require("./config");
const { loadUsers, saveUsers } = require("./data/store");
const { LanTransferService } = require("./services/lanTransfers");
const { startLanDiscovery } = require("./services/lanDiscovery");
const { renderError } = require("./utils/html");
const { getPreferredLanIp, getShareBaseUrl } = require("./utils/network");
const {
  createRateLimiter,
  hasOwn,
} = require("./utils/security");

const registerAuthRoutes = require("./routes/auth");
const registerAdminRoutes = require("./routes/admin");
const registerApiRoutes = require("./routes/api");
const registerLanRoutes = require("./routes/lan");

const ONE_HOUR_MS = 60 * 60 * 1000;
const FileStore = FileStoreFactory(session);

function wantsJson(req) {
  return req.path.startsWith("/api/") || req.path === "/upload" || req.path === "/guest-upload";
}

function configuredOrigins() {
  return [FRONTEND_BASE_URL, PUBLIC_BASE_URL]
    .filter(Boolean)
    .flatMap((value) => {
      try {
        return [new URL(value).origin];
      } catch {
        return [];
      }
    });
}

function lanRateLimitKey(req) {
  // Vite and reverse proxies can make every browser appear to originate from
  // one address. Pair the address with the short-lived LAN device identity so
  // one active browser cannot exhaust the presence budget for its colleagues.
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const deviceId = req.get("x-babyshare-device-id") || body.deviceId || req.query?.deviceId;
  if (typeof deviceId === "string" && /^[a-z0-9_-]{16,96}$/i.test(deviceId)) {
    return `lan:${req.ip || "unknown"}:${deviceId}`;
  }
  return `lan:${req.ip || "unknown"}`;
}

function createCorsMiddleware(allowedOrigins) {
  const allowed = new Set(allowedOrigins);
  return (req, res, next) => {
    const origin = req.get("origin");
    if (!origin) return next();
    if (!allowed.has(origin)) {
      if (req.method === "OPTIONS") return res.status(403).json({ error: "cross_origin_request" });
      return next();
    }

    res.vary("Origin");
    res.set({
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Headers": "Content-Type, X-BabyShare-Device-Id, X-BabyShare-Device-Token",
      "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Max-Age": "600",
    });
    if (req.method === "OPTIONS") return res.status(204).end();
    return next();
  };
}

function createSameOriginGuard(allowedOrigins) {
  const configuredOriginSet = new Set(allowedOrigins);

  return (req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();

    const source = req.get("origin") || req.get("referer");
    if (!source) return res.status(403).json({ error: "origin_required" });

    let sourceOrigin;
    try {
      sourceOrigin = new URL(source).origin;
    } catch {
      return res.status(403).json({ error: "invalid_origin" });
    }

    const scheme = req.secure ? "https" : "http";
    const requestOrigin = `${scheme}://${req.get("host")}`;
    if (sourceOrigin === requestOrigin || configuredOriginSet.has(sourceOrigin)) return next();
    return res.status(403).json({ error: "cross_origin_request" });
  };
}

function createApp() {
  validateRuntimeConfig();
  const app = express();
  if (TRUST_PROXY) app.set("trust proxy", 1);
  const allowedOrigins = configuredOrigins();

  app.disable("x-powered-by");
  const helmet = require("helmet");
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          baseUri: ["'self'"],
          connectSrc: ["'self'", ...allowedOrigins],
          fontSrc: ["'self'", "data:"],
          formAction: ["'self'"],
          frameAncestors: ["'self'"],
          imgSrc: ["'self'", "data:", "blob:"],
          mediaSrc: ["'self'", "blob:"],
          objectSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
        },
      },
      hsts: IS_PRODUCTION ? { maxAge: 31536000, includeSubDomains: true } : false,
      referrerPolicy: { policy: "same-origin" },
    })
  );

  app.use(createCorsMiddleware(allowedOrigins));

  app.use(express.urlencoded({ extended: false, limit: "64kb" }));
  app.use(express.json({ limit: "64kb" }));

  const sessionDirectory = path.join(DATA_DIR, "sessions");
  fs.mkdirSync(sessionDirectory, { recursive: true });
  app.use(
    session({
      cookie: {
        httpOnly: true,
        maxAge: SESSION_MAX_AGE_MS,
        sameSite: CROSS_ORIGIN_FRONTEND ? "none" : "lax",
        secure: HTTPS_ENABLED || (IS_PRODUCTION && TRUST_PROXY),
      },
      name: "babyshare.sid",
      resave: false,
      saveUninitialized: false,
      secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
      store: new FileStore({ logFn: () => {}, path: sessionDirectory, retries: 0, ttl: Math.ceil(SESSION_MAX_AGE_MS / 1000) }),
    })
  );

  const USERS = loadUsers();

  // Existing plaintext records are upgraded before requests can authenticate.
  for (const [username, password] of Object.entries(USERS)) {
    if (typeof password !== "string") throw new Error(`User store contains an invalid password record for ${username}`);
  }
  const plainTextUsers = Object.entries(USERS).filter(([, password]) => !password.startsWith("$2"));
  if (plainTextUsers.length > 0) {
    for (const [username, password] of plainTextUsers) {
      USERS[username] = bcrypt.hashSync(password, 12);
    }
    saveUsers(USERS);
  }

  const LAN_TRANSFERS = new LanTransferService();

  function appRedirect(res, redirectPath) {
    const base = FRONTEND_BASE_URL.replace(/\/+$/, "");
    return res.redirect(base ? `${base}${redirectPath}` : redirectPath);
  }

  function requireLogin(req, res, next) {
    if (req.session.user && hasOwn(USERS, req.session.user)) return next();
    if (wantsJson(req)) return res.status(401).json({ error: "unauthorized" });
    return appRedirect(res, "/login");
  }

  function requireAdmin(req, res, next) {
    if (req.session.user === "admin") return next();
    return res.status(403).json({ error: "forbidden" });
  }

  function cleanup() {
    LAN_TRANSFERS.cleanup();
  }

  cleanup();
  const cleanupTimer = setInterval(cleanup, ONE_HOUR_MS);
  cleanupTimer.unref();

  const loginLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
  // Presence refreshes make four requests per second, and an active WebRTC
  // transfer also polls for short-lived negotiation signals. Keep this limit
  // comfortably above normal usage while still constraining each device.
  const lanLimiter = createRateLimiter({ key: lanRateLimitKey, windowMs: 60 * 1000, max: 600 });

  if (HAS_DIST) app.use(express.static(DIST_DIR, { index: false, maxAge: IS_PRODUCTION ? "1h" : 0 }));

  app.get("/healthz", (_req, res) => res.status(200).json({ status: "ok" }));
  app.get("/", (req, res) => {
    if (req.session.user && hasOwn(USERS, req.session.user)) return res.redirect("/dashboard");
    if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
    return res.status(500).send("Frontend build missing. Run: npm run build");
  });

  const sharedDependencies = {
    DIST_DIR,
    FRONTEND_BASE_URL,
    HAS_DIST,
    LAN_TRANSFERS,
    USERS,
    WEBRTC_SIGNALING_ENABLED,
    appRedirect,
    lanLimiter,
    loginLimiter,
    renderError,
    requireAdmin,
    requireLogin,
    saveUsers,
  };

  app.use(createSameOriginGuard(allowedOrigins));
  registerApiRoutes(app, sharedDependencies);
  registerLanRoutes(app, sharedDependencies);
  registerAuthRoutes(app, sharedDependencies);
  registerAdminRoutes(app, sharedDependencies);

  // Legacy upload URLs remain explicit about the privacy model instead of
  // accepting multipart data. Direct WebRTC flows use /api/lan or /api/qr.
  app.post(["/upload", "/guest-upload"], (_req, res) => res.status(409).json({ error: "direct_connection_required" }));

  app.use((error, req, res, _next) => {
    if (res.headersSent) return;
    if (wantsJson(req)) return res.status(400).json({ error: "invalid_request" });
    return res.status(400).send("invalid_request");
  });

  if (HAS_DIST) {
    app.get(/.*/, (_req, res) => res.sendFile(path.join(DIST_DIR, "index.html")));
  }

  return app;
}

function startServers() {
  const app = createApp();
  const lanServicePort = LAN_DISCOVERY_PORT || (HTTPS_ENABLED && SHARE_USE_HTTPS ? PORT : HTTP_PORT);
  let discoveryStarted = false;
  const startDiscovery = () => {
    if (discoveryStarted) return;
    discoveryStarted = true;
    startLanDiscovery({ servicePort: lanServicePort, serviceProtocol: LAN_DISCOVERY_PROTOCOL });
  };
  if (HTTPS_ENABLED) {
    const key = fs.readFileSync(CERT_KEY_PATH);
    const cert = fs.readFileSync(CERT_CRT_PATH);
    https.createServer({ cert, key }, app).listen(PORT, BIND_HOST, () => {
      console.info(`BabyShare listening on https://localhost:${PORT}`);
      console.info(`Configured share base: ${getShareBaseUrl()}`);
      startDiscovery();
    });
    if (HTTP_PORT !== PORT) http.createServer(app).listen(HTTP_PORT, BIND_HOST);
    return;
  }

  app.listen(PORT, BIND_HOST, () => {
    console.info(`BabyShare listening on http://localhost:${PORT}`);
    console.info(`LAN address: http://${getPreferredLanIp()}:${PORT}`);
    startDiscovery();
  });
}

module.exports = { createApp, startServers };
