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
  DATA_DIR,
  DIST_DIR,
  FRONTEND_BASE_URL,
  HAS_DIST,
  HTTPS_ENABLED,
  HTTP_PORT,
  IS_PRODUCTION,
  PORT,
  PUBLIC_BASE_URL,
  SHARE_USE_HTTPS,
  SESSION_MAX_AGE_MS,
  validateRuntimeConfig,
} = require("./config");
const { loadUsers, loadShares, saveUsers, saveShares } = require("./data/store");
const { decryptFile, encryptFile, ensureDir } = require("./services/storage");
const { LanTransferService } = require("./services/lanTransfers");
const { startLanDiscovery } = require("./services/lanDiscovery");
const { renderError, renderGuestAccess, renderPasswordPrompt } = require("./utils/html");
const { getPreferredLanIp, getShareBaseUrl } = require("./utils/network");
const {
  createRateLimiter,
  hasOwn,
  isExpired,
  resolveWithin,
} = require("./utils/security");

const registerAuthRoutes = require("./routes/auth");
const registerFileRoutes = require("./routes/files");
const registerGuestRoutes = require("./routes/guest");
const registerAdminRoutes = require("./routes/admin");
const registerApiRoutes = require("./routes/api");
const registerLanRoutes = require("./routes/lan");

const ONE_HOUR_MS = 60 * 60 * 1000;
const FileStore = FileStoreFactory(session);

function wantsJson(req) {
  return req.path.startsWith("/api/") || req.path === "/upload" || req.path === "/guest-upload";
}

function createSameOriginGuard() {
  const configuredOrigins = [FRONTEND_BASE_URL, PUBLIC_BASE_URL]
    .filter(Boolean)
    .flatMap((value) => {
      try {
        return [new URL(value).origin];
      } catch {
        return [];
      }
    });

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
    if (sourceOrigin === requestOrigin || configuredOrigins.includes(sourceOrigin)) return next();
    return res.status(403).json({ error: "cross_origin_request" });
  };
}

function createApp() {
  validateRuntimeConfig();
  const app = express();
  const trustProxy = process.env.TRUST_PROXY === "true";
  if (trustProxy) app.set("trust proxy", 1);

  app.disable("x-powered-by");
  const helmet = require("helmet");
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          baseUri: ["'self'"],
          connectSrc: ["'self'"],
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

  app.use(express.urlencoded({ extended: false, limit: "64kb" }));
  app.use(express.json({ limit: "64kb" }));

  const sessionDirectory = path.join(DATA_DIR, "sessions");
  ensureDir(sessionDirectory);
  app.use(
    session({
      cookie: {
        httpOnly: true,
        maxAge: SESSION_MAX_AGE_MS,
        sameSite: "lax",
        secure: HTTPS_ENABLED || (IS_PRODUCTION && trustProxy),
      },
      name: "babyshare.sid",
      resave: false,
      saveUninitialized: false,
      secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
      store: new FileStore({ logFn: () => {}, path: sessionDirectory, retries: 0, ttl: Math.ceil(SESSION_MAX_AGE_MS / 1000) }),
    })
  );

  const USERS = loadUsers();
  const SHARES = loadShares();
  if (!SHARES.users || typeof SHARES.users !== "object") SHARES.users = {};
  if (!SHARES.guests || typeof SHARES.guests !== "object") SHARES.guests = {};

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

  const rawKey = process.env.FILE_KEY || "development-only-file-key";
  const SECRET_KEY = crypto.createHash("sha256").update(rawKey).digest();
  const UPLOADS_USERS = path.join(DATA_DIR, "uploads", "users");
  const UPLOADS_GUESTS = path.join(DATA_DIR, "uploads", "guests");
  const UPLOADS_TMP = path.join(DATA_DIR, "uploads", "tmp");
  const UPLOADS_LAN = path.join(DATA_DIR, "uploads", "lan");
  const LAN_TRANSFER_TMP = path.join(DATA_DIR, "uploads", "lan-tmp");
  ensureDir(UPLOADS_USERS);
  ensureDir(UPLOADS_GUESTS);
  ensureDir(UPLOADS_TMP);
  ensureDir(UPLOADS_LAN);
  ensureDir(LAN_TRANSFER_TMP);
  const LAN_TRANSFERS = new LanTransferService({ uploadDirectory: UPLOADS_LAN });

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

  function getUserFileMeta(username, filename) {
    if (!hasOwn(USERS, username) || typeof filename !== "string") return null;
    const entries = Array.isArray(SHARES.users[username]) ? SHARES.users[username] : [];
    return entries.find((item) => item && item.file === filename) || null;
  }

  function getUserFilePath(username, filename) {
    if (!getUserFileMeta(username, filename)) return null;
    return resolveWithin(UPLOADS_USERS, username, filename);
  }

  function mapUserFiles(username) {
    const entries = Array.isArray(SHARES.users[username]) ? SHARES.users[username] : [];
    return entries
      .filter((item) => item && !isExpired(item) && getUserFilePath(username, item.file) && fs.existsSync(getUserFilePath(username, item.file)))
      .map((item) => ({
        expires: item.expires || null,
        file: item.file,
        label: item.label || "",
        original: item.original,
        passwordProtected: Boolean(item.hash),
        uploaded: item.uploaded || null,
      }));
  }

  function removeUserShare(username, filename) {
    const entries = Array.isArray(SHARES.users[username]) ? SHARES.users[username] : [];
    SHARES.users[username] = entries.filter((item) => item && item.file !== filename);
    saveShares(SHARES);
  }

  function cleanup() {
    const now = Date.now();
    let changed = false;

    for (const [token, share] of Object.entries(SHARES.guests)) {
      const filePath = share && resolveWithin(UPLOADS_GUESTS, share.filename || "");
      if (!share || isExpired(share, now) || !filePath || !fs.existsSync(filePath)) {
        if (filePath && fs.existsSync(filePath)) {
          try {
            fs.unlinkSync(filePath);
            const directory = path.dirname(filePath);
            if (directory !== UPLOADS_GUESTS && fs.existsSync(directory) && fs.readdirSync(directory).length === 0) {
              fs.rmdirSync(directory);
            }
          } catch {
            // A future cleanup pass can retry a transient filesystem failure.
          }
        }
        delete SHARES.guests[token];
        changed = true;
      }
    }

    for (const [username, entries] of Object.entries(SHARES.users)) {
      if (!Array.isArray(entries)) {
        SHARES.users[username] = [];
        changed = true;
        continue;
      }
      const active = entries.filter((file) => {
        if (!file || isExpired(file, now)) {
          const filePath = file && resolveWithin(UPLOADS_USERS, username, file.file || "");
          if (filePath && fs.existsSync(filePath)) {
            try {
              fs.unlinkSync(filePath);
            } catch {
              return true;
            }
          }
          changed = true;
          return false;
        }
        return true;
      });
      SHARES.users[username] = active;
    }

    if (changed) saveShares(SHARES);
    LAN_TRANSFERS.cleanup();
  }

  cleanup();
  const cleanupTimer = setInterval(cleanup, ONE_HOUR_MS);
  cleanupTimer.unref();

  const loginLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
  const uploadLimiter = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 30 });
  const passwordLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });

  if (HAS_DIST) app.use(express.static(DIST_DIR, { index: false, maxAge: IS_PRODUCTION ? "1h" : 0 }));

  app.get("/healthz", (_req, res) => res.status(200).json({ status: "ok" }));
  app.get("/", (req, res) => {
    if (req.session.user) return res.redirect("/dashboard");
    if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
    return res.status(500).send("Frontend build missing. Run: npm run build");
  });

  const sharedDependencies = {
    DIST_DIR,
    FRONTEND_BASE_URL,
    HAS_DIST,
    LAN_TRANSFERS,
    LAN_TRANSFER_TMP,
    SECRET_KEY,
    SHARES,
    UPLOADS_GUESTS,
    UPLOADS_TMP,
    UPLOADS_USERS,
    USERS,
    appRedirect,
    decryptFile,
    encryptFile,
    getShareBaseUrl,
    getUserFileMeta,
    getUserFilePath,
    isExpired,
    loginLimiter,
    mapUserFiles,
    passwordLimiter,
    removeUserShare,
    renderError,
    renderGuestAccess,
    renderPasswordPrompt,
    requireAdmin,
    requireLogin,
    resolveWithin,
    saveShares,
    saveUsers,
    uploadLimiter,
  };

  app.use(createSameOriginGuard());
  registerApiRoutes(app, sharedDependencies);
  registerLanRoutes(app, sharedDependencies);
  registerAuthRoutes(app, sharedDependencies);
  registerFileRoutes(app, sharedDependencies);
  registerGuestRoutes(app, sharedDependencies);
  registerAdminRoutes(app, sharedDependencies);

  app.use((error, req, res, _next) => {
    const multerError = error && error.name === "MulterError";
    const status = multerError && error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
    const payload = multerError && error.code === "LIMIT_FILE_SIZE" ? "file_too_large" : "invalid_request";
    if (res.headersSent) return;
    if (wantsJson(req)) return res.status(status).json({ error: payload });
    return res.status(status).send(payload);
  });

  if (HAS_DIST) {
    app.get(/.*/, (_req, res) => res.sendFile(path.join(DIST_DIR, "index.html")));
  }

  return app;
}

function startServers() {
  const app = createApp();
  const lanServicePort = HTTPS_ENABLED && SHARE_USE_HTTPS ? PORT : HTTP_PORT;
  let discoveryStarted = false;
  const startDiscovery = () => {
    if (discoveryStarted) return;
    discoveryStarted = true;
    startLanDiscovery({ servicePort: lanServicePort });
  };
  if (HTTPS_ENABLED) {
    const key = fs.readFileSync(CERT_KEY_PATH);
    const cert = fs.readFileSync(CERT_CRT_PATH);
    https.createServer({ cert, key }, app).listen(PORT, "0.0.0.0", () => {
      console.info(`BabyShare listening on https://localhost:${PORT}`);
      console.info(`Configured share base: ${getShareBaseUrl()}`);
      startDiscovery();
    });
    if (HTTP_PORT !== PORT) http.createServer(app).listen(HTTP_PORT, "0.0.0.0");
    return;
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.info(`BabyShare listening on http://localhost:${PORT}`);
    console.info(`LAN address: http://${getPreferredLanIp()}:${PORT}`);
    startDiscovery();
  });
}

module.exports = { createApp, startServers };
