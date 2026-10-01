const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const test = require("node:test");

const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "babyshare-direct-test-"));
process.env.BBS_DATA_DIR = testDataDir;
process.env.SESSION_SECRET = "test-session-secret-that-is-long-enough-for-the-suite";
process.env.NODE_ENV = "test";
process.env.PORT = "0";
process.env.HTTP_PORT = "0";
process.env.FRONTEND_BASE_URL = "http://localhost:3000";

fs.writeFileSync(path.join(testDataDir, "users.json"), JSON.stringify({
  alice: bcrypt.hashSync("alice-password-123", 12),
  bob: bcrypt.hashSync("bob-password-123", 12),
}));

const { createApp } = require("../src/server");
let server;
let baseUrl;

function fetchApp(pathname, options = {}) { return fetch(`${baseUrl}${pathname}`, options); }

async function login(username, password) {
  const response = await fetchApp("/login", {
    body: new URLSearchParams({ password, username }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
    redirect: "manual",
  });
  assert.equal(response.status, 302);
  return response.headers.get("set-cookie").split(";", 1)[0];
}

function identity() {
  return { deviceId: crypto.randomUUID().replaceAll("-", ""), deviceToken: crypto.randomBytes(36).toString("base64url"), platform: "Test browser" };
}

function headers(device, json = true) {
  return { ...(json ? { "Content-Type": "application/json" } : {}), "x-babyshare-device-id": device.deviceId, "x-babyshare-device-token": device.deviceToken, Origin: baseUrl };
}

async function announce(device, cookie) {
  const response = await fetchApp("/api/lan/presence", {
    body: JSON.stringify(device),
    headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}), Origin: baseUrl },
    method: "POST",
  });
  assert.equal(response.status, 200);
}

test.before(async () => {
  server = http.createServer(createApp());
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await fs.promises.rm(testDataDir, { recursive: true, force: true });
});

test("login session survives follow-up requests", async () => {
  const cookie = await login("alice", "alice-password-123");
  const me = await fetchApp("/api/me", { headers: { Cookie: cookie } });
  assert.deepEqual(await me.json(), { isAdmin: false, user: "alice" });
});

test("authenticated and guest upload endpoints reject bytes instead of storing them", async () => {
  const cookie = await login("alice", "alice-password-123");
  const data = new FormData();
  data.append("files", new Blob(["must never reach server storage"]), "private.txt");
  const authenticated = await fetchApp("/upload", { body: data, headers: { Cookie: cookie, Origin: baseUrl }, method: "POST" });
  assert.equal(authenticated.status, 409);
  assert.equal((await authenticated.json()).error, "direct_connection_required");

  const guest = await fetchApp("/guest-upload", { body: data, headers: { Origin: baseUrl }, method: "POST" });
  assert.equal(guest.status, 409);
  assert.equal(fs.existsSync(path.join(testDataDir, "uploads")), false);
});

test("recipient-approved direct transfer keeps only metadata on BabyShare", async () => {
  const sender = identity();
  const recipient = identity();
  await announce(sender);
  await announce(recipient);

  const requested = await fetchApp("/api/lan/transfers/request", {
    body: JSON.stringify({ files: [{ name: "project.txt", relativePath: "handoff/project.txt", size: 20 }], recipientId: recipient.deviceId }),
    headers: headers(sender), method: "POST",
  });
  assert.equal(requested.status, 201);
  const transfer = (await requested.json()).transfers[0];
  assert.equal(transfer.transport, "peer");
  assert.equal(transfer.relativePath, "handoff/project.txt");

  const accepted = await fetchApp(`/api/lan/transfers/${transfer.id}/accept`, { body: JSON.stringify({}), headers: headers(recipient), method: "POST" });
  assert.equal(accepted.status, 200);
  const started = await fetchApp(`/api/lan/transfers/${transfer.id}/peer-start`, { body: JSON.stringify({}), headers: headers(sender), method: "POST" });
  assert.equal(started.status, 200);
  const progress = await fetchApp(`/api/lan/transfers/${transfer.id}/peer-progress`, { body: JSON.stringify({ bytesTransferred: 20 }), headers: headers(sender), method: "POST" });
  assert.equal(progress.status, 200);
  const completed = await fetchApp(`/api/lan/transfers/${transfer.id}/peer-complete`, { body: JSON.stringify({}), headers: headers(recipient), method: "POST" });
  assert.equal(completed.status, 200);
  assert.equal((await completed.json()).transfer.status, "completed");

  const relayAttempt = await fetchApp(`/api/lan/transfers/${transfer.id}/content`, { body: new Blob(["bytes"]), headers: { Origin: baseUrl }, method: "POST" });
  assert.equal(relayAttempt.status, 404);
  assert.equal(fs.existsSync(path.join(testDataDir, "uploads")), false);
});

test("either participant can cancel a pending direct transfer and signaling contains metadata only", async () => {
  const sender = identity();
  const recipient = identity();
  await announce(sender);
  await announce(recipient);
  const requested = await fetchApp("/api/lan/transfers/request", {
    body: JSON.stringify({ files: [{ name: "cancel.txt", size: 1 }], recipientId: recipient.deviceId }), headers: headers(sender), method: "POST",
  });
  const transfer = (await requested.json()).transfers[0];
  const cancelled = await fetchApp(`/api/lan/transfers/${transfer.id}/cancel`, { body: JSON.stringify({}), headers: headers(recipient), method: "POST" });
  assert.equal(cancelled.status, 200);
  assert.equal((await cancelled.json()).transfer.status, "cancelled");

  const signal = await fetchApp("/api/lan/signals", {
    body: JSON.stringify({ recipientId: recipient.deviceId, signal: { sessionId: "direct-session-123", type: "offer" } }), headers: headers(sender), method: "POST",
  });
  assert.equal(signal.status, 202);
  const signals = await fetchApp("/api/lan/signals", { headers: headers(recipient, false) });
  assert.equal((await signals.json()).signals[0].signal.type, "offer");
});
