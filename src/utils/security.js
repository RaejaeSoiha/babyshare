// Security-focused validation and lightweight, dependency-free request limits.
const path = require("path");

const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{2,31}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const PASSWORD_MIN_LENGTH = 4;

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function normalizeUsername(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isValidUsername(value) {
  return USERNAME_PATTERN.test(normalizeUsername(value));
}

function isValidPassword(value) {
  return typeof value === "string" && value.length >= PASSWORD_MIN_LENGTH && value.length <= 128;
}

function isValidLabel(value) {
  return typeof value === "string" && value.length <= 120 && !CONTROL_CHARACTERS.test(value);
}

function isValidUploadName(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 240) return false;
  if (CONTROL_CHARACTERS.test(value)) return false;
  return path.basename(value) === value && path.win32.basename(value) === value;
}

function resolveWithin(baseDir, ...segments) {
  const base = path.resolve(baseDir);
  const target = path.resolve(base, ...segments);
  return target === base || target.startsWith(`${base}${path.sep}`) ? target : null;
}

function isExpired(item, now = Date.now()) {
  return Boolean(item && item.expires && Number(item.expires) <= now);
}

function isValidAction(value) {
  return value === "preview" || value === "download";
}

function createRateLimiter({ windowMs, max, key = (req) => req.ip || "unknown" }) {
  const entries = new Map();

  return (req, res, next) => {
    const now = Date.now();
    const bucketKey = key(req);
    const entry = entries.get(bucketKey);
    const active = entry && entry.resetAt > now ? entry : { count: 0, resetAt: now + windowMs };
    active.count += 1;
    entries.set(bucketKey, active);

    if (active.count > max) {
      res.setHeader("Retry-After", Math.ceil((active.resetAt - now) / 1000));
      return res.status(429).json({ error: "rate_limited" });
    }
    return next();
  };
}

module.exports = {
  createRateLimiter,
  hasOwn,
  isExpired,
  isValidAction,
  isValidLabel,
  PASSWORD_MIN_LENGTH,
  isValidPassword,
  isValidUploadName,
  isValidUsername,
  normalizeUsername,
  resolveWithin,
};
