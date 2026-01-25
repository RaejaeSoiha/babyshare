// Main Express entrypoint: app setup, shared state, routes, and server startup.
const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const http = require("http");
const https = require("https");
require("dotenv").config();

const { PORT, HTTP_PORT, CERT_KEY_PATH, CERT_CRT_PATH, HTTPS_ENABLED, DIST_DIR, HAS_DIST, ROOT_DIR } = require("./config");
const { loadUsers, loadShares, saveUsers, saveShares } = require("./data/store");
const { ensureDir, encryptFile, decryptFile } = require("./services/storage");
const { renderError, renderSuccess, renderAccessOptions } = require("./utils/html");
const { getPreferredLanIp, getBaseUrl, getShareBaseUrl } = require("./utils/network");

const registerAuthRoutes = require("./routes/auth");
const registerFileRoutes = require("./routes/files");
const registerGuestRoutes = require("./routes/guest");
const registerAdminRoutes = require("./routes/admin");
const registerApiRoutes = require("./routes/api");

const app = express();

// Security headers (LAN-safe). We avoid strict policies that break local/HTTP access.
const helmet = require("helmet");
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginOpenerPolicy: false,
    originAgentCluster: false,
    hsts: false,
  })
);
app.use((req, res, next) => {
  res.removeHeader("Cross-Origin-Opener-Policy");
  res.removeHeader("Origin-Agent-Cluster");
  res.removeHeader("Strict-Transport-Security");
  next();
});

// Body parsing for form posts and JSON APIs.
app.use(express.urlencoded({ extended: true, limit: "1gb" }));
app.use(express.json({ limit: "1gb" }));

// Session cookie for login state.
app.use(
  session({
    secret: process.env.SESSION_SECRET || "fallback-secret",
    resave: false,
    saveUninitialized: true,
  })
);

if (HAS_DIST) {
  app.use(express.static(DIST_DIR));
}

// Data stores (users + share metadata).
const USERS = loadUsers();
const SHARES = loadShares();
if (!SHARES.users) SHARES.users = {};
if (!SHARES.guests) SHARES.guests = {};

// Auto-migrate plaintext passwords to bcrypt hashes on startup.
(async () => {
  let changed = false;
  for (const [user, pass] of Object.entries(USERS)) {
    if (!pass.startsWith("$2")) {
      USERS[user] = await bcrypt.hash(pass, 10);
      changed = true;
    }
  }
  if (changed) saveUsers(USERS);
})();

// Derive a fixed-length key for symmetric encryption.
const RAW_KEY = process.env.FILE_KEY || "fallback-secret-key";
const SECRET_KEY = crypto.createHash("sha256").update(RAW_KEY).digest();

// Paths used across modules.
const UPLOADS_USERS = path.join(ROOT_DIR, "uploads", "users");
const UPLOADS_GUESTS = path.join(ROOT_DIR, "uploads", "guests");
ensureDir(UPLOADS_USERS);
ensureDir(UPLOADS_GUESTS);
ensureDir(path.join(ROOT_DIR, "uploads", "tmp"));

// Simple auth guards for route protection.
function requireLogin(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}

function requireAdmin(req, res, next) {
  if (req.session.user === "admin") return next();
  res.status(403).send("Admins only");
}

function mapUserFiles(username) {
  const entries = SHARES.users[username] || [];
  return entries
    .filter((item) => fs.existsSync(path.join(UPLOADS_USERS, username, item.file)))
    .map((item) => ({
      file: item.file,
      original: item.original,
      label: item.label || "",
      uploaded: item.uploaded || null,
      expires: item.expires || null,
      passwordProtected: Boolean(item.hash),
    }));
}

// Cleanup expired shares and orphaned files on an interval.
function cleanup() {
  const now = Date.now();

  Object.keys(SHARES.guests || {}).forEach((t) => {
    const g = SHARES.guests[t];
    if (!g || g.expires < now) {
      if (g && fs.existsSync(g.filename)) {
        try {
          fs.unlinkSync(g.filename);
          const dir = path.dirname(g.filename);
          if (fs.existsSync(dir) && fs.readdirSync(dir).length === 0) {
            fs.rmdirSync(dir);
          }
        } catch {
          // ignore
        }
      }
      delete SHARES.guests[t];
    }
  });

  Object.keys(SHARES.users || {}).forEach((u) => {
    SHARES.users[u] = (SHARES.users[u] || []).filter((file) => {
      if (file.expires && file.expires < now) {
        const fp = path.join(UPLOADS_USERS, u, file.file);
        if (fs.existsSync(fp)) {
          try {
            fs.unlinkSync(fp);
          } catch {
            // ignore
          }
        }
        return false;
      }
      return true;
    });
  });

  saveShares(SHARES);
  console.log("?? Cleanup done at", new Date().toISOString());
}
cleanup();
setInterval(cleanup, 60 * 60 * 1000);

// Routes (API + pages).
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
  return res.status(500).send("Frontend build missing. Run: npm run build");
});

registerApiRoutes(app, { USERS, SHARES, requireLogin, mapUserFiles });
registerAuthRoutes(app, {
  HAS_DIST,
  DIST_DIR,
  ROOT_DIR,
  USERS,
  SHARES,
  saveUsers,
  saveShares,
  ensureDir,
  UPLOADS_USERS,
});
registerFileRoutes(app, {
  SECRET_KEY,
  UPLOADS_USERS,
  USERS,
  SHARES,
  saveShares,
  ensureDir,
  encryptFile,
  decryptFile,
  renderAccessOptions,
  requireLogin,
  requireAdmin,
  mapUserFiles,
  getShareBaseUrl,
});
registerGuestRoutes(app, {
  SECRET_KEY,
  SHARES,
  saveShares,
  ensureDir,
  encryptFile,
  decryptFile,
  UPLOADS_GUESTS,
  getShareBaseUrl,
});
registerAdminRoutes(app, {
  USERS,
  SHARES,
  saveUsers,
  saveShares,
  ensureDir,
  UPLOADS_USERS,
  requireLogin,
  requireAdmin,
  HAS_DIST,
  DIST_DIR,
});

if (HAS_DIST) {
  // SPA fallback: allow React Router to handle deep links.
  app.get("*", (req, res) => {
    res.sendFile(path.join(DIST_DIR, "index.html"));
  });
}

// Start servers: HTTPS if enabled, always expose HTTP for share links when configured.
if (HTTPS_ENABLED) {
  const key = fs.readFileSync(CERT_KEY_PATH);
  const cert = fs.readFileSync(CERT_CRT_PATH);
  https.createServer({ key, cert }, app).listen(PORT, "0.0.0.0", () => {
    console.log(`BabyShare running at https://localhost:${PORT}`);
    console.log(`LAN access (HTTPS): https://${getPreferredLanIp()}:${PORT}`);
    console.log(`LAN access (HTTP): http://${getPreferredLanIp()}:${HTTP_PORT}`);
  });
  if (HTTP_PORT !== PORT) {
    http.createServer(app).listen(HTTP_PORT, "0.0.0.0");
  }
} else {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`BabyShare running at http://localhost:${PORT}`);
    console.log(`LAN access: http://${getPreferredLanIp()}:${PORT}`);
    if (HTTP_PORT !== PORT) {
      console.log(`Share links: http://${getPreferredLanIp()}:${HTTP_PORT}`);
    }
  });
  if (HTTP_PORT !== PORT) {
    http.createServer(app).listen(HTTP_PORT, "0.0.0.0");
  }
}
