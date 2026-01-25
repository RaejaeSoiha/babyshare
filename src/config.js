// Central runtime configuration (ports, paths, feature flags).
const fs = require("fs");
const path = require("path");

// Project root for resolving file paths.
const ROOT_DIR = path.join(__dirname, "..");
const PORT = process.env.PORT || 3000;
const HTTP_PORT = process.env.HTTP_PORT || 3001;

const CERT_KEY_PATH = path.join(ROOT_DIR, "certs", "selfsigned.key");
const CERT_CRT_PATH = path.join(ROOT_DIR, "certs", "selfsigned.crt");

// HTTPS is only enabled when forced and certs exist.
const HTTPS_ENABLED =
  process.env.FORCE_HTTPS === "true" &&
  fs.existsSync(CERT_KEY_PATH) &&
  fs.existsSync(CERT_CRT_PATH);
// Whether share links should be HTTPS (only if HTTPS is enabled).
const SHARE_USE_HTTPS = process.env.SHARE_USE_HTTPS === "true";

// Built frontend output for production.
const DIST_DIR = path.join(ROOT_DIR, "client", "dist");
const HAS_DIST = fs.existsSync(DIST_DIR);

module.exports = {
  ROOT_DIR,
  PORT,
  HTTP_PORT,
  CERT_KEY_PATH,
  CERT_CRT_PATH,
  HTTPS_ENABLED,
  SHARE_USE_HTTPS,
  DIST_DIR,
  HAS_DIST,
};
