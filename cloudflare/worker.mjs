// Cloudflare production runtime. The Node/Express server remains the local LAN runtime.
// This free-plan runtime never receives or stores file bytes: transfers stay
// between approved nearby browsers over WebRTC.

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_MAX_AGE_MS = 8 * 60 * 60 * 1000;
const DEVICE_TTL_MS = 45_000;
const PENDING_TTL_MS = 10 * 60 * 1000;
const ACCEPTED_TTL_MS = 20 * 60 * 1000;
const READY_TTL_MS = DAY_MS;
const MAX_FILE_SIZE = 1024 * 1024 * 1024;
const MAX_ACTIVE_TRANSFERS_PER_DEVICE = 20;
const MAX_CHAT_MESSAGES = 200;
const MAX_CHAT_MESSAGE_LENGTH = 1_000;
const MAX_SIGNAL_BYTES = 32 * 1024;
const MAX_SIGNALS_PER_DEVICE = 24;
const SIGNAL_TTL_MS = 60 * 1000;
const QR_PAIR_TTL_MS = 10 * 60 * 1000;
const MAX_QR_SIGNALS = 48;
let qrCodeSchemaPromise;
// Workers Free allows 10 ms of CPU per request. Keep password operations below
// that limit in the Cloudflare runtime; the separate Node/LAN server retains
// its existing password implementation.
const PASSWORD_ITERATIONS = 10_000;

function json(value, init = {}) {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(value), { ...init, headers });
}

function empty(status = 204, headers) {
  return new Response(null, { headers, status });
}

function html(value, status = 200, headers) {
  const result = new Headers(headers);
  result.set("Content-Type", "text/html; charset=utf-8");
  result.set("Cache-Control", "private, no-store, max-age=0");
  result.set("Referrer-Policy", "same-origin");
  return new Response(value, { headers: result, status });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderDocument(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="same-origin"><title>${escapeHtml(title)} | BabyShare</title><style>body{align-items:center;background:#0b0f16;color:#eef2f7;display:flex;font:16px system-ui,sans-serif;justify-content:center;margin:0;min-height:100vh;padding:24px}main{background:#141a24;border:1px solid #334155;border-radius:8px;box-shadow:0 18px 40px rgba(0,0,0,.35);max-width:420px;padding:28px;width:100%}h1{font-size:1.5rem;margin:0 0 8px}p{color:#c8d3ea;line-height:1.5}input{box-sizing:border-box;margin:12px 0;padding:12px;width:100%}.actions{display:flex;flex-wrap:wrap;gap:10px}button,a{background:#1faa6f;border:0;border-radius:6px;color:white;cursor:pointer;font:inherit;padding:10px 14px;text-decoration:none}.alt{background:#1f9cf3}</style></head><body><main>${body}</main></body></html>`;
}

function renderError(title, message) {
  return renderDocument(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><a href="/">Return home</a>`);
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64UrlBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomHex(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function constantTimeEquals(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function normalizedUsername(value) {
  return typeof value === "string" ? value.trim() : "";
}

function validUsername(value) {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{2,31}$/.test(normalizedUsername(value));
}

function validPassword(value) {
  return typeof value === "string" && value.length >= 4 && value.length <= 128;
}

function validFileName(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 240
    && !/[\u0000-\u001f\u007f]/.test(value)
    && !value.includes("/")
    && !value.includes("\\");
}

function formValue(form, name) {
  const value = form.get(name);
  return typeof value === "string" ? value : "";
}

async function discardRequestBody(request) {
  if (request.body) await request.body.cancel().catch(() => {});
}

async function passwordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ hash: "SHA-256", iterations: PASSWORD_ITERATIONS, name: "PBKDF2", salt }, material, 256);
  return `pbkdf2-sha256$${PASSWORD_ITERATIONS}$${base64Url(salt)}$${base64Url(new Uint8Array(bits))}`;
}

async function passwordMatches(password, encoded) {
  if (typeof encoded !== "string") return false;
  const [algorithm, iterationsValue, saltValue, digestValue] = encoded.split("$");
  const iterations = Number.parseInt(iterationsValue || "", 10);
  // New Worker accounts use the Free-plan-safe iteration count above. Accept
  // only that format here too: the previous 100k minimum rejected every
  // account created by this Worker, while accepting an arbitrary larger value
  // risks exceeding the Worker CPU limit during sign-in.
  if (algorithm !== "pbkdf2-sha256" || iterations !== PASSWORD_ITERATIONS || !saltValue || !digestValue) return false;
  try {
    const material = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ hash: "SHA-256", iterations, name: "PBKDF2", salt: base64UrlBytes(saltValue) }, material, 256);
    return constantTimeEquals(new Uint8Array(bits), base64UrlBytes(digestValue));
  } catch {
    return false;
  }
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", textEncoder.encode(secret), { hash: "SHA-256", name: "HMAC" }, false, ["sign"]);
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, textEncoder.encode(value))));
}

function cookieValue(request, name) {
  const prefix = `${name}=`;
  return (request.headers.get("Cookie") || "").split(";").map((item) => item.trim()).find((item) => item.startsWith(prefix))?.slice(prefix.length) || "";
}

function sessionCookie(value, maxAge = Math.ceil(SESSION_MAX_AGE_MS / 1000)) {
  return `babyshare.sid=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function createSession(env, username) {
  const id = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_MAX_AGE_MS;
  await env.DB.prepare("INSERT INTO sessions (id, username, expires_at, created_at) VALUES (?, ?, ?, ?)").bind(id, username, expiresAt, Date.now()).run();
  const payload = `${id}.${expiresAt}`;
  return { cookie: sessionCookie(`${payload}.${await hmac(payload, env.SESSION_SECRET)}`), expiresAt, id };
}

async function currentSession(request, env) {
  if (!env.SESSION_SECRET) return null;
  const [id, expiresValue, signature] = cookieValue(request, "babyshare.sid").split(".");
  const expiresAt = Number.parseInt(expiresValue || "", 10);
  if (!id || !signature || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) return null;
  const expected = await hmac(`${id}.${expiresAt}`, env.SESSION_SECRET);
  if (!constantTimeEquals(textEncoder.encode(signature), textEncoder.encode(expected))) return null;
  const session = await env.DB.prepare("SELECT username, expires_at FROM sessions WHERE id = ?").bind(id).first();
  if (!session || Number(session.expires_at) <= Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
    return null;
  }
  return { id, username: String(session.username) };
}

async function ensureBootstrapAdmin(env) {
  const username = normalizedUsername(env.BOOTSTRAP_ADMIN_USERNAME || "");
  const password = env.BOOTSTRAP_ADMIN_PASSWORD || "";
  if (!validUsername(username) || !validPassword(password)) return;
  const exists = await env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
  if (!exists) {
    await env.DB.prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)")
      .bind(username, await passwordHash(password), Date.now()).run();
  }
}

function bootstrapCredentialsMatch(env, username, password) {
  const bootstrapUsername = normalizedUsername(env.BOOTSTRAP_ADMIN_USERNAME || "");
  const bootstrapPassword = env.BOOTSTRAP_ADMIN_PASSWORD || "";
  return validUsername(bootstrapUsername)
    && validPassword(bootstrapPassword)
    && username === bootstrapUsername
    && constantTimeEquals(textEncoder.encode(password), textEncoder.encode(bootstrapPassword));
}

async function recoverBootstrapAdmin(env, username, password) {
  if (!bootstrapCredentialsMatch(env, username, password)) return false;
  const now = Date.now();
  const passwordHashValue = await passwordHash(password);
  await env.DB.prepare(
    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?) ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash",
  ).bind(username, passwordHashValue, now).run();
  await env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(username).run();
  return true;
}

function sameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  return !origin || origin === url.origin;
}

function requireSameOrigin(request, url) {
  return sameOrigin(request, url) ? null : json({ error: "cross_origin_request" }, { status: 403 });
}

async function requireUser(request, env) {
  return currentSession(request, env);
}

async function peerOnly(request) {
  await discardRequestBody(request);
  const message = "Cloudflare Free mode sends files directly between approved nearby browsers and does not store uploads or download links.";
  if (request.method === "GET" && !request.headers.get("Accept")?.includes("application/json")) {
    return html(renderError("Direct transfer only", message), 410);
  }
  return json({ error: "peer_only", message }, { status: 410 });
}

async function serveSpa(request, env) {
  const indexUrl = new URL("/index.html", request.url);
  return env.ASSETS.fetch(new Request(indexUrl, { headers: request.headers, method: "GET" }));
}

async function handleLogin(request, env) {
  const form = await request.formData();
  const username = normalizedUsername(formValue(form, "username"));
  const password = formValue(form, "password");
  const recoveredBootstrapAdmin = await recoverBootstrapAdmin(env, username, password);
  if (!recoveredBootstrapAdmin) {
    const user = await env.DB.prepare("SELECT password_hash FROM users WHERE username = ?").bind(username).first();
    if (!user || !(await passwordMatches(password, String(user.password_hash)))) {
      return html(renderError("Unable to sign in", "Check your username and password, then try again."), 401);
    }
  }
  if (!env.SESSION_SECRET) {
    return html(renderError("Sign-in is not configured", "The workspace is missing its encrypted session secret. Add SESSION_SECRET in Worker settings, then try again."), 503);
  }
  const session = await createSession(env, username);
  return new Response(null, { headers: { Location: "/dashboard", "Set-Cookie": session.cookie }, status: 302 });
}

async function handleRegister(request, env) {
  const form = await request.formData();
  const username = normalizedUsername(formValue(form, "username"));
  const password = formValue(form, "password");
  if (!validUsername(username) || !validPassword(password)) {
    return html(renderError("Invalid account details", "Use a 3-32 character username and a password of at least 4 characters."), 400);
  }
  const existing = await env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
  if (existing) return html(renderError("Username unavailable", "Choose a different username."), 409);
  await env.DB.prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)")
    .bind(username, await passwordHash(password), Date.now()).run();
  return new Response(null, { headers: { Location: "/login?created=1" }, status: 302 });
}

async function handleFiles(request, env, session) {
  if (!session) return json({ error: "unauthorized" }, { status: 401 });
  if (session.username === "admin") {
    const users = (await env.DB.prepare("SELECT username FROM users ORDER BY username").all()).results || [];
    return json({ isAdmin: true, users: users.map((row) => ({ files: [], username: String(row.username) })) });
  }
  return json({ files: [], isAdmin: false, user: session.username });
}

async function handleAdmin(request, env, session, url) {
  if (!session) return json({ error: "unauthorized" }, { status: 401 });
  if (session.username !== "admin") return json({ error: "forbidden" }, { status: 403 });
  if (url.pathname === "/api/admin/overview") {
    const users = await env.DB.prepare("SELECT COUNT(*) AS count FROM users").first();
    return json({ guestsCount: 0, usersCount: Number(users?.count || 0) });
  }
  if (url.pathname === "/api/admin/users" && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT username FROM users ORDER BY username").all();
    return json({ users: (rows.results || []).map((row) => ({ fileCount: 0, username: String(row.username) })) });
  }
  if (url.pathname === "/api/admin/users" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = normalizedUsername(body.username);
    const password = typeof body.password === "string" ? body.password : "";
    if (!validUsername(username) || !validPassword(password)) return json({ error: "invalid_account" }, { status: 400 });
    const exists = await env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
    if (exists) return json({ error: "user_exists" }, { status: 409 });
    await env.DB.prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)").bind(username, await passwordHash(password), Date.now()).run();
    return json({ ok: true }, { status: 201 });
  }
  const reset = /^\/api\/admin\/users\/([^/]+)\/reset$/u.exec(url.pathname);
  if (reset && request.method === "POST") {
    const username = decodeURIComponent(reset[1]);
    const body = await request.json().catch(() => ({}));
    const password = typeof body.newPassword === "string" ? body.newPassword : "";
    if (username === "admin") return json({ error: "protected" }, { status: 403 });
    if (!validPassword(password)) return json({ error: "invalid_password" }, { status: 400 });
    const result = await env.DB.prepare("UPDATE users SET password_hash = ? WHERE username = ?").bind(await passwordHash(password), username).run();
    if (!result.meta.changes) return json({ error: "not_found" }, { status: 404 });
    return empty();
  }
  const remove = /^\/api\/admin\/users\/([^/]+)$/u.exec(url.pathname);
  if (remove && request.method === "DELETE") {
    const username = decodeURIComponent(remove[1]);
    if (username === "admin") return json({ error: "protected" }, { status: 403 });
    const result = await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
    if (!result.meta.changes) return json({ error: "not_found" }, { status: 404 });
    return empty();
  }
  return json({ error: "not_found" }, { status: 404 });
}

async function cloudLanScope(request, env, session) {
  if (!env.LAN_SCOPE_SECRET) return null;
  // Signed-in accounts belong to the same private BabyShare workspace, so a
  // phone and computer can discover each other even when IPv6, mobile data,
  // or a VPN makes Cloudflare see different public IP addresses. Anonymous
  // guests remain isolated to their current public connection.
  if (session?.username) return hmac("workspace:authenticated", env.LAN_SCOPE_SECRET);
  const clientAddress = request.headers.get("CF-Connecting-IP") || "unknown";
  return hmac(`lan:${clientAddress}`, env.LAN_SCOPE_SECRET);
}

async function proxyLan(request, env, session) {
  const scope = await cloudLanScope(request, env, session);
  if (!scope) return json({ error: "lan_not_configured" }, { status: 503 });
  // Clone before adding trusted Worker-only headers. Constructing a request
  // from the original body with overridden headers can leave a streaming
  // multipart body locked when the Durable Object sends its response.
  const forwarded = new Request(request);
  forwarded.headers.set("x-babyshare-scope", scope);
  forwarded.headers.set("x-babyshare-user", session?.username || "");
  const id = env.LAN_HUB.idFromName(scope);
  return env.LAN_HUB.get(id).fetch(forwarded);
}

async function proxyQrPairing(request, env, url) {
  if (!env.QR_HUB) return json({ error: "qr_not_configured" }, { status: 503 });
  await ensureQrCodeSchema(env);
  const codeMatch = /^\/api\/qr\/pairings\/by-code\/(\d{8})$/u.exec(url.pathname);
  if (codeMatch && request.method === "GET") {
    const pair = await env.DB.prepare("SELECT pair_token FROM qr_pair_codes WHERE code = ? AND expires_at > ?").bind(codeMatch[1], Date.now()).first();
    return pair ? json({ pairToken: String(pair.pair_token) }) : json({ error: "pairing_expired" }, { status: 404 });
  }
  if (url.pathname === "/api/qr/pairings" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (!validTransferFile(body.file)) return json({ error: "invalid_transfer" }, { status: 400 });
    const pairToken = randomHex(16);
    const senderSecret = randomHex(24);
    const expiresAt = Date.now() + QR_PAIR_TTL_MS;
    let shortCode = "";
    for (let attempt = 0; attempt < 4 && !shortCode; attempt += 1) {
      const candidate = String(Math.floor(10_000_000 + Math.random() * 90_000_000));
      const inserted = await env.DB.prepare("INSERT OR IGNORE INTO qr_pair_codes (code, pair_token, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(candidate, pairToken, expiresAt, Date.now()).run();
      if (inserted.meta.changes) shortCode = candidate;
    }
    if (!shortCode) return json({ error: "pairing_unavailable" }, { status: 503 });
    const target = new URL(`/api/qr/pairings/${pairToken}/create`, url);
    const created = await env.QR_HUB.get(env.QR_HUB.idFromName(pairToken)).fetch(new Request(target, {
      body: JSON.stringify({ expiresAt, file: body.file, senderSecret }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    }));
    const payload = await created.json().catch(() => ({}));
    if (!created.ok) return json(payload, { status: created.status });
    return json({
      expiresAt,
      pairToken,
      senderSecret,
      shortCode,
      url: new URL(`/guest-receive?pair=${pairToken}`, url).toString(),
    }, { status: 201 });
  }
  const match = /^\/api\/qr\/pairings\/([a-f0-9]{32})\/(claim|accept|status|signals|complete)$/iu.exec(url.pathname);
  if (!match || !validQrPairToken(match[1])) {
    await discardRequestBody(request);
    return json({ error: "not_found" }, { status: 404 });
  }
  return env.QR_HUB.get(env.QR_HUB.idFromName(match[1])).fetch(request);
}

function ensureQrCodeSchema(env) {
  if (!qrCodeSchemaPromise) {
    qrCodeSchemaPromise = Promise.all([
      env.DB.prepare("CREATE TABLE IF NOT EXISTS qr_pair_codes (code TEXT PRIMARY KEY, pair_token TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)").run(),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS qr_pair_codes_expiry_idx ON qr_pair_codes(expires_at)").run(),
    ]).catch((error) => {
      qrCodeSchemaPromise = undefined;
      throw error;
    });
  }
  return qrCodeSchemaPromise;
}

async function cleanupExpired(env) {
  const now = Date.now();
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now).run();
  await env.DB.prepare("DELETE FROM qr_pair_codes WHERE expires_at <= ?").bind(now).run();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return sameOrigin(request, url) ? empty() : json({ error: "cross_origin_request" }, { status: 403 });
    if (!["GET", "HEAD", "OPTIONS"].includes(request.method)) {
      const rejected = requireSameOrigin(request, url);
      if (rejected) return rejected;
    }
    try {
      if (url.pathname === "/healthz") return json({ status: "ok" });
      if (url.pathname === "/" && request.method === "GET") {
        const session = await currentSession(request, env);
        return session
          ? Response.redirect(new URL("/dashboard", url), 302)
          : env.ASSETS.fetch(request);
      }
      if (
        url.pathname === "/upload"
        || url.pathname === "/guest-view"
        || url.pathname === "/guest-download"
        || url.pathname === "/guest-login"
        || url.pathname.startsWith("/secure-download/")
        || url.pathname.startsWith("/download/")
        || url.pathname.startsWith("/api/guest-info/")
        || (url.pathname.startsWith("/api/files/") && request.method === "DELETE")
      ) return peerOnly(request);
      if (url.pathname.startsWith("/api/qr/")) return proxyQrPairing(request, env, url);
      if (url.pathname.startsWith("/api/lan/")) return proxyLan(request, env, await currentSession(request, env));
      if (["/login", "/register", "/api/me", "/api/files", "/upload", "/logout"].includes(url.pathname) || url.pathname.startsWith("/api/admin/")) {
        await ensureBootstrapAdmin(env);
      }
      if (url.pathname === "/login") return request.method === "POST" ? handleLogin(request, env) : serveSpa(request, env);
      if (url.pathname === "/register") return request.method === "POST" ? handleRegister(request, env) : serveSpa(request, env);
      if (["/guest-receive", "/guest-upload"].includes(url.pathname)) return request.method === "GET" ? serveSpa(request, env) : peerOnly(request);
      if (url.pathname === "/logout" && request.method === "POST") {
        const session = await currentSession(request, env);
        if (session) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(session.id).run();
        return empty(204, { "Set-Cookie": sessionCookie("", 0) });
      }
      if (url.pathname === "/api/me") {
        const session = await currentSession(request, env);
        return session ? json({ isAdmin: session.username === "admin", user: session.username }) : json({ error: "unauthorized" }, { status: 401 });
      }
      if (url.pathname === "/api/files" && request.method === "GET") return handleFiles(request, env, await requireUser(request, env));
      if (url.pathname.startsWith("/api/admin/")) return handleAdmin(request, env, await requireUser(request, env), url);
      if (/^\/delete\/[^/]+\/[^/]+$/u.test(url.pathname)) {
        return new Response("Use the file management page to delete a file", { status: 405 });
      }
      if (["/dashboard", "/files", "/admin", "/settings", "/home", "/list", "/manage-users", "/guest-receive", "/guest-upload", "/guest-login"].includes(url.pathname)) return serveSpa(request, env);
      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error("Cloudflare Worker request failed", error);
      return url.pathname.startsWith("/api/") || ["/upload", "/guest-receive", "/guest-upload"].includes(url.pathname)
        ? json({ error: "server_error" }, { status: 500 })
        : html(renderError("Service unavailable", "BabyShare could not complete that request. Please try again."), 500);
    }
  },
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));
  },
};

function validDeviceId(value) {
  return typeof value === "string" && /^[a-z0-9_-]{16,96}$/i.test(value);
}

function validDeviceToken(value) {
  return typeof value === "string" && /^[a-z0-9_-]{24,192}$/i.test(value);
}

function cleanName(value, fallback) {
  if (typeof value !== "string") return fallback;
  const cleaned = value.replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, 80);
  return cleaned || fallback;
}

function validTransferFile(file) {
  return file && typeof file === "object" && validFileName(file.name) && Number.isSafeInteger(file.size) && file.size > 0 && file.size <= MAX_FILE_SIZE
    && (file.relativePath === undefined || (typeof file.relativePath === "string" && file.relativePath.length <= 500 && !file.relativePath.includes("..")));
}

function validSignal(signal) {
  if (!signal || typeof signal !== "object" || Array.isArray(signal)) return false;
  if (!["offer", "answer", "candidate", "hangup"].includes(signal.type)) return false;
  if (typeof signal.sessionId !== "string" || !/^[a-z0-9_-]{8,96}$/i.test(signal.sessionId)) return false;
  try {
    return textEncoder.encode(JSON.stringify(signal)).byteLength <= MAX_SIGNAL_BYTES;
  } catch {
    return false;
  }
}

function validQrPairToken(value) {
  return typeof value === "string" && /^[a-f0-9]{32}$/i.test(value);
}

export class BabyShareLanHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.devices = new Map();
    this.chats = new Map();
    this.transfers = new Map();
    this.signals = new Map();
  }

  async tokenDigest(value) {
    return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", textEncoder.encode(value))));
  }

  async heartbeat(payload, scope, user) {
    const { deviceId, deviceToken, deviceName, platform } = payload || {};
    if (!validDeviceId(deviceId) || !validDeviceToken(deviceToken)) return null;
    const tokenHash = await this.tokenDigest(deviceToken);
    const existing = this.devices.get(deviceId);
    if (existing && !constantTimeEquals(textEncoder.encode(existing.tokenHash), textEncoder.encode(tokenHash))) return null;
    const normalizedPlatform = cleanName(platform, "Browser");
    const displayName = cleanName(user, "Guest");
    const device = {
      deviceName: cleanName(deviceName, `${normalizedPlatform} device`), displayName, id: deviceId, name: displayName,
      platform: normalizedPlatform, scope, tokenHash, updatedAt: Date.now(),
    };
    this.devices.set(deviceId, device);
    return device;
  }

  async authorized(headers, url, allowQuery = false) {
    const deviceId = headers.get("x-babyshare-device-id") || (allowQuery ? url.searchParams.get("deviceId") : "");
    const deviceToken = headers.get("x-babyshare-device-token") || (allowQuery ? url.searchParams.get("deviceToken") : "");
    const scope = headers.get("x-babyshare-scope") || "";
    if (!validDeviceId(deviceId) || !validDeviceToken(deviceToken)) return null;
    const device = this.devices.get(deviceId);
    if (!device || device.scope !== scope || device.updatedAt + DEVICE_TTL_MS < Date.now()) return null;
    return constantTimeEquals(textEncoder.encode(device.tokenHash), textEncoder.encode(await this.tokenDigest(deviceToken))) ? device : null;
  }

  cleanUp() {
    const now = Date.now();
    for (const [id, device] of this.devices) if (device.updatedAt + DEVICE_TTL_MS < now) this.devices.delete(id);
    for (const [id, chat] of this.chats) {
      // Convert chats that survived from a prior Worker version. Chat messages
      // now connect immediately; only file transfers require approval.
      if (chat.status === "pending") { chat.status = "active"; chat.updatedAt = now; }
      if (chat.status === "active") {
        const sender = this.devices.get(chat.senderId);
        const recipient = this.devices.get(chat.recipientId);
        if (!sender || !recipient || sender.updatedAt + DEVICE_TTL_MS < now || recipient.updatedAt + DEVICE_TTL_MS < now) this.chats.delete(id);
      }
    }
    for (const [id, transfer] of this.transfers) {
      const ttl = transfer.status === "pending" ? PENDING_TTL_MS : ["accepted", "receiving"].includes(transfer.status) ? ACCEPTED_TTL_MS : READY_TTL_MS;
      if (transfer.updatedAt + ttl >= now) continue;
      this.transfers.delete(id);
    }
    for (const [deviceId, queue] of this.signals) {
      const active = queue.filter((entry) => entry.createdAt + SIGNAL_TTL_MS >= now);
      if (active.length) this.signals.set(deviceId, active); else this.signals.delete(deviceId);
    }
  }

  sameScopeRecipient(sender, recipientId) {
    const recipient = this.devices.get(recipientId);
    return recipient && recipient.scope === sender.scope && recipient.updatedAt + DEVICE_TTL_MS >= Date.now() ? recipient : null;
  }

  clientChat(chat, device) {
    const outgoing = chat.senderId === device.id;
    return {
      createdAt: chat.createdAt, direction: outgoing ? "outgoing" : "incoming", id: chat.id,
      messages: chat.status === "active" ? chat.messages.map((message) => ({ id: message.id, mine: message.senderId === device.id, sentAt: message.sentAt, text: message.text })) : [],
      peerId: outgoing ? chat.recipientId : chat.senderId, peerName: outgoing ? chat.recipientName : chat.senderName,
      status: chat.status, updatedAt: chat.updatedAt,
    };
  }

  clientTransfer(transfer, device) {
    const outgoing = transfer.senderId === device.id;
    const progress = transfer.status === "completed" ? 100 : transfer.size > 0 ? Math.min(99, Math.round((transfer.bytesTransferred / transfer.size) * 100)) : 0;
    return {
      createdAt: transfer.createdAt, direction: outgoing ? "outgoing" : "incoming", id: transfer.id, name: transfer.name, relativePath: transfer.relativePath || undefined,
      peerId: outgoing ? transfer.recipientId : transfer.senderId, peerName: outgoing ? transfer.recipientName : transfer.senderName,
      progress, size: transfer.size, status: transfer.status, transport: transfer.transport, updatedAt: transfer.updatedAt,
    };
  }

  getTransferForSender(id, device) {
    const transfer = this.transfers.get(id);
    return transfer?.senderId === device.id ? transfer : null;
  }

  getTransferForRecipient(id, device) {
    const transfer = this.transfers.get(id);
    return transfer?.recipientId === device.id ? transfer : null;
  }

  getChat(id, device) {
    const chat = this.chats.get(id);
    return chat && (chat.senderId === device.id || chat.recipientId === device.id) ? chat : null;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const scope = request.headers.get("x-babyshare-scope") || "";
    if (!scope) return json({ error: "lan_not_configured" }, { status: 503 });
    this.cleanUp();
    if (url.pathname === "/api/lan/presence" && request.method === "POST") {
      const device = await this.heartbeat(await request.json().catch(() => null), scope, request.headers.get("x-babyshare-user") || "");
      return device ? json({ ok: true }) : json({ error: "invalid_device" }, { status: 400 });
    }
    const device = await this.authorized(request.headers, url);
    if (!device) {
      await discardRequestBody(request);
      return json({ error: "device_unauthorized" }, { status: 403 });
    }
    if (url.pathname === "/api/lan/devices" && request.method === "GET") {
      const devices = [...this.devices.values()].filter((candidate) => candidate.id !== device.id && candidate.scope === device.scope && candidate.updatedAt + DEVICE_TTL_MS >= Date.now())
        .sort((left, right) => right.updatedAt - left.updatedAt || left.name.localeCompare(right.name))
        .map(({ deviceName, displayName, id, platform }) => ({ deviceName, displayName, id, online: true, platform }));
      return json({ devices });
    }
    if (url.pathname === "/api/lan/chats" && request.method === "GET") {
      return json({ chats: [...this.chats.values()].filter((chat) => chat.senderId === device.id || chat.recipientId === device.id).sort((left, right) => right.updatedAt - left.updatedAt).map((chat) => this.clientChat(chat, device)) });
    }
    if (url.pathname === "/api/lan/transfers" && request.method === "GET") {
      return json({ transfers: [...this.transfers.values()].filter((transfer) => transfer.senderId === device.id || transfer.recipientId === device.id).sort((left, right) => right.updatedAt - left.updatedAt).map((transfer) => this.clientTransfer(transfer, device)) });
    }
    if (url.pathname === "/api/lan/signals") {
      if (request.method === "GET") {
        const signals = (this.signals.get(device.id) || []).filter((entry) => entry.scope === device.scope).map(({ createdAt, id, senderId, signal }) => ({ createdAt, id, senderId, signal }));
        this.signals.delete(device.id);
        return json({ signals });
      }
      if (request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const recipient = this.sameScopeRecipient(device, body.recipientId);
        if (!validSignal(body.signal) || !recipient || recipient.id === device.id) return json({ error: recipient ? "invalid_signal" : "device_unavailable" }, { status: recipient ? 400 : 404 });
        const queue = this.signals.get(recipient.id) || [];
        if (queue.length >= MAX_SIGNALS_PER_DEVICE) queue.splice(0, queue.length - MAX_SIGNALS_PER_DEVICE + 1);
        const relay = { createdAt: Date.now(), id: crypto.randomUUID(), senderId: device.id, signal: JSON.parse(JSON.stringify(body.signal)), scope: device.scope };
        queue.push(relay); this.signals.set(recipient.id, queue);
        return json({ signal: { id: relay.id, queued: true } }, { status: 202 });
      }
    }
    if (url.pathname === "/api/lan/chats/request" && request.method === "POST") {
      const recipient = this.sameScopeRecipient(device, (await request.json().catch(() => ({}))).recipientId);
      if (!recipient || recipient.id === device.id) return json({ error: recipient ? "invalid_device" : "device_unavailable" }, { status: recipient ? 400 : 404 });
      const existing = [...this.chats.values()].find((chat) => ["pending", "active"].includes(chat.status) && ((chat.senderId === device.id && chat.recipientId === recipient.id) || (chat.senderId === recipient.id && chat.recipientId === device.id)));
      if (existing) return json({ chat: this.clientChat(existing, device) }, { status: 201 });
      const now = Date.now();
      // Conversations connect immediately. Recipient approval continues to be
      // required for file transfers, but not for chat messages.
      const chat = { createdAt: now, id: crypto.randomUUID(), messages: [], recipientId: recipient.id, recipientName: recipient.name, senderId: device.id, senderName: device.name, status: "active", updatedAt: now };
      this.chats.set(chat.id, chat);
      return json({ chat: this.clientChat(chat, device) }, { status: 201 });
    }
    const chatAction = /^\/api\/lan\/chats\/([^/]+)\/(accept|messages|end)$/u.exec(url.pathname);
    if (chatAction) {
      const chat = this.getChat(chatAction[1], device);
      if (!chat) {
        await discardRequestBody(request);
        return json({ error: "chat_unavailable" }, { status: 404 });
      }
      if (chatAction[2] === "accept" && request.method === "POST") {
        await request.json().catch(() => ({}));
        if (chat.recipientId !== device.id || !["pending", "active"].includes(chat.status)) return json({ error: "chat_unavailable" }, { status: 404 });
        if (chat.status === "pending") { chat.status = "active"; chat.updatedAt = Date.now(); }
        return json({ chat: this.clientChat(chat, device) });
      }
      if (chatAction[2] === "messages" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const message = typeof body.text === "string" ? body.text.replace(/\u0000/g, "").trim() : "";
        if (chat.status !== "active" || !message || message.length > MAX_CHAT_MESSAGE_LENGTH) return json({ error: "invalid_chat_message" }, { status: 400 });
        chat.messages.push({ id: crypto.randomUUID(), senderId: device.id, sentAt: Date.now(), text: message });
        if (chat.messages.length > MAX_CHAT_MESSAGES) chat.messages.splice(0, chat.messages.length - MAX_CHAT_MESSAGES);
        chat.updatedAt = Date.now(); return json({ chat: this.clientChat(chat, device) }, { status: 201 });
      }
      if (chatAction[2] === "end" && request.method === "POST") { await request.json().catch(() => ({})); this.chats.delete(chat.id); return empty(); }
    }
    if (url.pathname === "/api/lan/transfers/request" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const recipient = this.sameScopeRecipient(device, body.recipientId);
      const files = Array.isArray(body.files) ? body.files : [];
      if (!recipient) return json({ error: "device_unavailable" }, { status: 404 });
      if (recipient.id === device.id || files.length === 0 || files.length > 20 || files.some((file) => !validTransferFile(file))) return json({ error: "invalid_transfer" }, { status: 400 });
      const active = (transfer) => ["pending", "accepted", "receiving"].includes(transfer.status);
      const senderCount = [...this.transfers.values()].filter((transfer) => transfer.senderId === device.id && active(transfer)).length;
      const recipientCount = [...this.transfers.values()].filter((transfer) => transfer.recipientId === recipient.id && active(transfer)).length;
      if (senderCount + files.length > MAX_ACTIVE_TRANSFERS_PER_DEVICE || recipientCount + files.length > MAX_ACTIVE_TRANSFERS_PER_DEVICE) return json({ error: "transfer_limit_reached" }, { status: 400 });
      const now = Date.now();
      const transfers = files.map((file) => {
        const transfer = { bytesTransferred: 0, createdAt: now, id: crypto.randomUUID(), name: file.name, relativePath: typeof file.relativePath === "string" ? file.relativePath : "", recipientId: recipient.id, recipientName: recipient.name, senderId: device.id, senderName: device.name, size: file.size, status: "pending", transport: "peer", updatedAt: now };
        this.transfers.set(transfer.id, transfer); return this.clientTransfer(transfer, device);
      });
      return json({ transfers }, { status: 201 });
    }
    const transferAction = /^\/api\/lan\/transfers\/([^/]+)\/(accept|decline|peer-start|peer-progress|peer-complete|cancel)$/u.exec(url.pathname);
    if (transferAction) return this.handleTransferAction(request, url, device, transferAction[1], transferAction[2]);
    await discardRequestBody(request);
    return json({ error: "not_found" }, { status: 404 });
  }

  async handleTransferAction(request, url, device, id, operation) {
    const recipientOperation = ["accept", "decline", "peer-complete"].includes(operation);
    const transfer = operation === "cancel"
      ? (this.getTransferForRecipient(id, device) || this.getTransferForSender(id, device))
      : recipientOperation ? this.getTransferForRecipient(id, device) : this.getTransferForSender(id, device);
    if (!transfer) {
      await discardRequestBody(request);
      return json({ error: "transfer_unavailable" }, { status: 409 });
    }
    if (operation === "accept" && request.method === "POST") {
      await request.json().catch(() => ({}));
      if (transfer.status !== "pending") return json({ error: "transfer_unavailable" }, { status: 409 });
      transfer.status = "accepted"; transfer.updatedAt = Date.now(); return json({ transfer: this.clientTransfer(transfer, device) });
    }
    if (operation === "decline" && request.method === "POST") {
      await request.json().catch(() => ({}));
      if (transfer.status !== "pending") return json({ error: "transfer_unavailable" }, { status: 404 });
      this.transfers.delete(id); return empty();
    }
    if (operation === "peer-start" && request.method === "POST") {
      await request.json().catch(() => ({}));
      if (transfer.status !== "accepted") return json({ error: "transfer_not_accepted" }, { status: 409 });
      transfer.transport = "peer"; transfer.status = "receiving"; transfer.bytesTransferred = 0; transfer.updatedAt = Date.now(); return json({ transfer: this.clientTransfer(transfer, device) });
    }
    if (operation === "peer-progress" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      if (transfer.transport !== "peer" || transfer.status !== "receiving" || !Number.isSafeInteger(body.bytesTransferred)) return json({ error: "transfer_unavailable" }, { status: 409 });
      transfer.bytesTransferred = Math.min(transfer.size, Math.max(0, body.bytesTransferred)); transfer.updatedAt = Date.now(); return json({ transfer: this.clientTransfer(transfer, device) });
    }
    if (operation === "peer-complete" && request.method === "POST") {
      await request.json().catch(() => ({}));
      if (transfer.transport !== "peer" || transfer.status !== "receiving" || transfer.bytesTransferred < transfer.size) return json({ error: "transfer_incomplete" }, { status: 409 });
      transfer.bytesTransferred = transfer.size; transfer.status = "completed"; transfer.updatedAt = Date.now(); return json({ transfer: this.clientTransfer(transfer, device) });
    }
    if (operation === "cancel" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      if (["completed", "cancelled", "failed"].includes(transfer.status)) return json({ error: "transfer_unavailable" }, { status: 409 });
      transfer.status = body.failed === true ? "failed" : "cancelled";
      transfer.updatedAt = Date.now();
      return json({ transfer: this.clientTransfer(transfer, device) });
    }
    await discardRequestBody(request);
    return json({ error: "not_found" }, { status: 404 });
  }
}

// A pairing exists only long enough to establish a WebRTC data channel. The
// Durable Object relays metadata and ICE/SDP messages only; file bytes are
// never accepted by this class or by the Worker.
export class BabyShareQrHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async currentPairing() {
    const pairing = await this.state.storage.get("pairing");
    if (!pairing) return null;
    if (Number(pairing.expiresAt) > Date.now()) return pairing;
    await this.state.storage.deleteAll();
    return null;
  }

  async savePairing(pairing) {
    await this.state.storage.put("pairing", pairing);
    await this.state.storage.setAlarm(pairing.expiresAt);
  }

  publicPairing(pairing) {
    return {
      expiresAt: pairing.expiresAt,
      file: { name: pairing.file.name, size: pairing.file.size },
      status: pairing.status,
    };
  }

  roleFor(request, pairing) {
    const secret = request.headers.get("x-babyshare-qr-secret") || "";
    if (!secret) return null;
    if (constantTimeEquals(textEncoder.encode(secret), textEncoder.encode(pairing.senderSecret))) return "sender";
    if (pairing.receiverSecret && constantTimeEquals(textEncoder.encode(secret), textEncoder.encode(pairing.receiverSecret))) return "receiver";
    return null;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.endsWith("/create") && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      if (!validTransferFile(body.file) || typeof body.senderSecret !== "string" || !/^[a-f0-9]{48}$/i.test(body.senderSecret)
        || !Number.isSafeInteger(body.expiresAt) || body.expiresAt <= Date.now() || body.expiresAt > Date.now() + QR_PAIR_TTL_MS + 10_000) {
        return json({ error: "invalid_pairing" }, { status: 400 });
      }
      const existing = await this.currentPairing();
      if (existing) return json({ error: "pairing_exists" }, { status: 409 });
      const pairing = {
        createdAt: Date.now(),
        expiresAt: body.expiresAt,
        file: { name: body.file.name, size: body.file.size },
        receiverSecret: "",
        senderSecret: body.senderSecret,
        signals: { receiver: [], sender: [] },
        status: "waiting",
        updatedAt: Date.now(),
      };
      await this.savePairing(pairing);
      return json({ pairing: this.publicPairing(pairing) }, { status: 201 });
    }

    const pairing = await this.currentPairing();
    if (!pairing) {
      await discardRequestBody(request);
      return json({ error: "pairing_expired" }, { status: 410 });
    }
    if (url.pathname.endsWith("/claim") && request.method === "POST") {
      await request.json().catch(() => ({}));
      const existingSecret = request.headers.get("x-babyshare-qr-secret") || "";
      if (pairing.receiverSecret) {
        if (!constantTimeEquals(textEncoder.encode(existingSecret), textEncoder.encode(pairing.receiverSecret))) return json({ error: "pairing_taken" }, { status: 409 });
        return json({ pairing: this.publicPairing(pairing), receiverSecret: pairing.receiverSecret });
      }
      pairing.receiverSecret = randomHex(24);
      pairing.status = "claimed";
      pairing.updatedAt = Date.now();
      await this.savePairing(pairing);
      return json({ pairing: this.publicPairing(pairing), receiverSecret: pairing.receiverSecret });
    }

    const role = this.roleFor(request, pairing);
    if (!role) {
      await discardRequestBody(request);
      return json({ error: "pairing_unauthorized" }, { status: 403 });
    }
    if (url.pathname.endsWith("/status") && request.method === "GET") return json({ pairing: this.publicPairing(pairing) });
    if (url.pathname.endsWith("/accept") && request.method === "POST") {
      await request.json().catch(() => ({}));
      if (role !== "receiver" || !["claimed", "accepted"].includes(pairing.status)) return json({ error: "pairing_unavailable" }, { status: 409 });
      pairing.status = "accepted";
      pairing.updatedAt = Date.now();
      await this.savePairing(pairing);
      return json({ pairing: this.publicPairing(pairing) });
    }
    if (url.pathname.endsWith("/signals")) {
      if (request.method === "GET") {
        const signals = pairing.signals[role] || [];
        pairing.signals[role] = [];
        pairing.updatedAt = Date.now();
        await this.savePairing(pairing);
        return json({ signals });
      }
      if (request.method === "POST") {
        const signal = (await request.json().catch(() => ({}))).signal;
        if (pairing.status !== "accepted" || !validSignal(signal)) return json({ error: "invalid_signal" }, { status: 400 });
        const recipientRole = role === "sender" ? "receiver" : "sender";
        const queue = pairing.signals[recipientRole] || [];
        if (queue.length >= MAX_QR_SIGNALS) queue.splice(0, queue.length - MAX_QR_SIGNALS + 1);
        queue.push(JSON.parse(JSON.stringify(signal)));
        pairing.signals[recipientRole] = queue;
        pairing.updatedAt = Date.now();
        await this.savePairing(pairing);
        return json({ ok: true }, { status: 202 });
      }
    }
    if (url.pathname.endsWith("/complete") && request.method === "POST") {
      await request.json().catch(() => ({}));
      if (!["accepted", "complete"].includes(pairing.status)) return json({ error: "pairing_unavailable" }, { status: 409 });
      pairing.status = "complete";
      pairing.updatedAt = Date.now();
      await this.savePairing(pairing);
      return json({ pairing: this.publicPairing(pairing) });
    }
    await discardRequestBody(request);
    return json({ error: "not_found" }, { status: 404 });
  }

  async alarm() {
    await this.state.storage.deleteAll();
  }
}
