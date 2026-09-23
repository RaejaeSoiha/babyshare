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
  for (const key of ["FILE_KEY", "SESSION_SECRET"]) {
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
const FRONTEND_BASE_URL = (process.env.FRONTEND_BASE_URL || "").trim().replace(/\/+$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || process.env.DOMAIN || "")
  .trim()
  .replace(/\/+$/, "");
const PORT = readPort(process.env.PORT, 3000);
const HTTP_PORT = readPort(process.env.HTTP_PORT, PORT);
const SESSION_MAX_AGE_MS = readPositiveInt(process.env.SESSION_MAX_AGE_MS, 8 * 60 * 60 * 1000);

const CERT_KEY_PATH = toAbsolutePath(process.env.TLS_KEY_PATH, path.join(ROOT_DIR, "certs", "selfsigned.key"));
const CERT_CRT_PATH = toAbsolutePath(process.env.TLS_CERT_PATH, path.join(ROOT_DIR, "certs", "selfsigned.crt"));
const HTTPS_ENABLED = process.env.FORCE_HTTPS === "true";
const SHARE_USE_HTTPS = process.env.SHARE_USE_HTTPS === "true";

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
    ["FILE_KEY", process.env.FILE_KEY],
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

  if (HTTPS_ENABLED && (!fs.existsSync(CERT_KEY_PATH) || !fs.existsSync(CERT_CRT_PATH))) {
    throw new Error("FORCE_HTTPS=true requires TLS_KEY_PATH and TLS_CERT_PATH to reference readable certificates");
  }
}

module.exports = {
  CERT_CRT_PATH,
  CERT_KEY_PATH,
  DATA_DIR,
  DIST_DIR,
  FRONTEND_BASE_URL,
  HAS_DIST,
  HTTPS_ENABLED,
  HTTP_PORT,
  IS_DESKTOP,
  IS_PRODUCTION,
  NODE_ENV,
  PORT,
  PUBLIC_BASE_URL,
  ROOT_DIR,
  SESSION_MAX_AGE_MS,
  SHARE_USE_HTTPS,
  validateRuntimeConfig,
};
