// Central runtime configuration (ports, paths, feature flags, and validation).
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";
const IS_DESKTOP = process.env.BBS_DESKTOP === "true";

function readPort(value, fallback) {
  const port = Number.parseInt(value || "", 10);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : fallback;
}

function readPositiveInt(value, fallback) {
  const number = Number.parseInt(value || "", 10);
  return Number.isInteger(number) && number > 0 ? number : fallback;
}

function readUrlOrigin(value) {
  if (!value) return "";
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function toAbsolutePath(value, fallback) {
  return path.resolve(value || fallback);
}

// Project root for resolving packaged application resources.
const ROOT_DIR = toAbsolutePath(process.env.BBS_ROOT_DIR, path.join(__dirname, ".."));
// Keep mutable runtime data outside the application image when configured.
const DATA_DIR = toAbsolutePath(process.env.BBS_DATA_DIR, ROOT_DIR);

function provisionDesktopSecrets() {
  if (!IS_DESKTOP) return;
  const secretsPath = path.join(DATA_DIR, "babyshare-secrets.json");
  let secrets = {};
  try {
    secrets = JSON.parse(fs.readFileSync(secretsPath, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error("Unable to read desktop secrets; restore the local secrets file before starting.");
  }

  let changed = false;
  for (const key of ["SESSION_SECRET"]) {
    if (typeof secrets[key] !== "string" || secrets[key].length < 32) {
      secrets[key] = crypto.randomBytes(48).toString("base64url");
      changed = true;
    }
    if (!process.env[key]) process.env[key] = secrets[key];
  }
  if (changed) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const temporary = `${secretsPath}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(secrets)}\n`, { encoding: "utf8", mode: 0o600 });
    fs.renameSync(temporary, secretsPath);
  }
}

provisionDesktopSecrets();
// The Vite client runs on this origin during local development and proxies API traffic to the backend.
// Treat it as a trusted same-origin frontend so state-changing requests retain CSRF protection when proxied.
const defaultDevelopmentFrontend = NODE_ENV === "development" && !IS_DESKTOP ? "http://localhost:3000" : "";
const FRONTEND_BASE_URL = (process.env.FRONTEND_BASE_URL || defaultDevelopmentFrontend).trim().replace(/\/+$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || process.env.DOMAIN || "")
  .trim()
  .replace(/\/+$/, "");
const PORT = readPort(process.env.PORT, 3000);
const HTTP_PORT = readPort(process.env.HTTP_PORT, PORT);
const SESSION_MAX_AGE_MS = readPositiveInt(process.env.SESSION_MAX_AGE_MS, 8 * 60 * 60 * 1000);
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const BIND_HOST = (process.env.BIND_HOST || "0.0.0.0").trim();
const configuredLanDiscoveryPort = readPort(process.env.LAN_DISCOVERY_PORT, 0);
const WEBRTC_SIGNALING_ENABLED = process.env.WEBRTC_SIGNALING_ENABLED !== "false";
const FRONTEND_ORIGIN = readUrlOrigin(FRONTEND_BASE_URL);
const PUBLIC_ORIGIN = readUrlOrigin(PUBLIC_BASE_URL);
const CROSS_ORIGIN_FRONTEND = Boolean(FRONTEND_ORIGIN && PUBLIC_ORIGIN && FRONTEND_ORIGIN !== PUBLIC_ORIGIN);

const CERT_KEY_PATH = toAbsolutePath(process.env.TLS_KEY_PATH, path.join(ROOT_DIR, "certs", "selfsigned.key"));
const CERT_CRT_PATH = toAbsolutePath(process.env.TLS_CERT_PATH, path.join(ROOT_DIR, "certs", "selfsigned.crt"));
const HTTPS_ENABLED = process.env.FORCE_HTTPS === "true";
const SHARE_USE_HTTPS = process.env.SHARE_USE_HTTPS === "true";
const defaultLanDiscoveryProtocol = HTTPS_ENABLED && SHARE_USE_HTTPS ? "https" : "http";
const LAN_DISCOVERY_PROTOCOL = process.env.LAN_DISCOVERY_PROTOCOL === "https" ? "https" : defaultLanDiscoveryProtocol;
const LAN_DISCOVERY_PORT = configuredLanDiscoveryPort || (LAN_DISCOVERY_PROTOCOL === "https" ? PORT : HTTP_PORT);

const distCandidates = [
  process.env.BBS_DIST_DIR,
  path.join(ROOT_DIR, "client", "dist"),
  path.join(path.dirname(process.execPath || ""), "resources", "dist"),
  path.join(path.dirname(process.execPath || ""), "..", "resources", "dist"),
].filter(Boolean);

let DIST_DIR = distCandidates[0] || path.join(ROOT_DIR, "client", "dist");
for (const candidate of distCandidates) {
  if (fs.existsSync(candidate)) {
    DIST_DIR = candidate;
    break;
  }
}
const HAS_DIST = fs.existsSync(DIST_DIR);

function isStrongSecret(value) {
  return typeof value === "string" && value.length >= 32;
}

function validateRuntimeConfig() {
  if (!IS_PRODUCTION) return;

  const required = [
    ["SESSION_SECRET", process.env.SESSION_SECRET],
  ];
  const missing = required.filter(([, value]) => !isStrongSecret(value)).map(([name]) => name);
  if (!IS_DESKTOP && !PUBLIC_BASE_URL) missing.push("PUBLIC_BASE_URL");
  if (missing.length > 0) {
    throw new Error(`Production configuration requires strong values for: ${missing.join(", ")}`);
  }

  if (!IS_DESKTOP) {
    try {
      const url = new URL(PUBLIC_BASE_URL);
      if (url.protocol !== "https:") {
        throw new Error("PUBLIC_BASE_URL must use HTTPS in production");
      }
    } catch (error) {
      if (error.message === "PUBLIC_BASE_URL must use HTTPS in production") throw error;
      throw new Error("PUBLIC_BASE_URL must be a valid HTTPS URL in production");
    }
  }

  if (FRONTEND_BASE_URL && !FRONTEND_ORIGIN) {
    throw new Error("FRONTEND_BASE_URL must be a valid URL when configured");
  }
  if (CROSS_ORIGIN_FRONTEND) {
    if (!FRONTEND_BASE_URL.startsWith("https://")) {
      throw new Error("A cross-origin FRONTEND_BASE_URL must use HTTPS in production");
    }
    if (!HTTPS_ENABLED && !TRUST_PROXY) {
      throw new Error("A cross-origin frontend requires FORCE_HTTPS=true or TRUST_PROXY=true in production");
    }
  }

  if (HTTPS_ENABLED && (!fs.existsSync(CERT_KEY_PATH) || !fs.existsSync(CERT_CRT_PATH))) {
    throw new Error("FORCE_HTTPS=true requires TLS_KEY_PATH and TLS_CERT_PATH to reference readable certificates");
  }
}

module.exports = {
  CERT_CRT_PATH,
  CERT_KEY_PATH,
  BIND_HOST,
  CROSS_ORIGIN_FRONTEND,
  DATA_DIR,
  DIST_DIR,
  FRONTEND_ORIGIN,
  FRONTEND_BASE_URL,
  HAS_DIST,
  HTTPS_ENABLED,
  HTTP_PORT,
  IS_DESKTOP,
  IS_PRODUCTION,
  LAN_DISCOVERY_PORT,
  LAN_DISCOVERY_PROTOCOL,
  NODE_ENV,
  PORT,
  PUBLIC_ORIGIN,
  PUBLIC_BASE_URL,
  ROOT_DIR,
  SESSION_MAX_AGE_MS,
  SHARE_USE_HTTPS,
  validateRuntimeConfig,
  TRUST_PROXY,
  WEBRTC_SIGNALING_ENABLED,
};
