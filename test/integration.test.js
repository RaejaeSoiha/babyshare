const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const test = require("node:test");

const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "babyshare-test-"));
process.env.BBS_DATA_DIR = testDataDir;
process.env.FILE_KEY = "test-file-key-that-is-long-enough-for-the-suite";
process.env.SESSION_SECRET = "test-session-secret-that-is-long-enough-for-the-suite";
process.env.NODE_ENV = "test";
process.env.PORT = "0";
process.env.HTTP_PORT = "0";
process.env.FRONTEND_BASE_URL = "http://localhost:3000";

const { encryptFile } = require("../src/services/storage");
const { createApp } = require("../src/server");

const users = {
  alice: bcrypt.hashSync("alice-password-123", 12),
  bob: bcrypt.hashSync("bob-password-123", 12),
};
const shares = {
  guests: {},
  users: {
    alice: [
      {
        expires: Date.now() + 60_000,
        file: "alice-secret.enc",
        label: "Alice secret",
        original: "alice-secret.txt",
        uploaded: Date.now(),
      },
      {
        expires: Date.now() + 60_000,
        file: "expired.enc",
        label: "Expired",
        original: "expired.txt",
        uploaded: Date.now(),
      },
      {
        expires: Date.now() + 60_000,
        file: "protected.enc",
        hash: bcrypt.hashSync("share-password-123", 12),
        label: "Protected",
        original: "protected.txt",
        uploaded: Date.now(),
      },
    ],
    bob: [
      {
        expires: Date.now() + 60_000,
        file: "bob-secret.enc",
        label: "Bob secret",
        original: "bob-secret.txt",
        uploaded: Date.now(),
      },
    ],
  },
};

fs.writeFileSync(path.join(testDataDir, "users.json"), JSON.stringify(users));
fs.writeFileSync(path.join(testDataDir, "shares.json"), JSON.stringify(shares));

const key = crypto.createHash("sha256").update(process.env.FILE_KEY).digest();
async function makeEncryptedFile(username, storedName, contents) {
  const directory = path.join(testDataDir, "uploads", "users", username);
  fs.mkdirSync(directory, { recursive: true });
  const source = path.join(directory, `${storedName}.source`);
  const target = path.join(directory, storedName);
  fs.writeFileSync(source, contents);
  await encryptFile(source, target, key);
}

let server;
let baseUrl;

async function fetchApp(pathname, options = {}) {
  return fetch(`${baseUrl}${pathname}`, options);
}

async function createGuestShare({
  contents = "iPhone QR transfer",
  filename = "phone-share.txt",
  password = "",
  type = "text/plain",
} = {}) {
  const form = new FormData();
  form.append("file", new Blob([contents], { type }), filename);
  if (password) form.append("password", password);
  const response = await fetchApp("/guest-upload", {
    body: form,
    headers: { Origin: baseUrl },
    method: "POST",
  });
  assert.equal(response.status, 201);
  return response.json();
}

async function login(username, password) {
  const response = await fetchApp("/login", {
    body: new URLSearchParams({ password, username }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
    redirect: "manual",
  });
  assert.equal(response.status, 302);
  const cookie = response.headers.get("set-cookie");
  assert.ok(cookie);
  return cookie.split(";", 1)[0];
}

function lanIdentity() {
  return {
    deviceId: crypto.randomUUID().replace(/-/g, ""),
    deviceToken: crypto.randomBytes(36).toString("base64url"),
    name: "Test device",
    platform: "Test browser",
  };
}

function lanHeaders(identity, json = true) {
  return {
    ...(json ? { "Content-Type": "application/json" } : {}),
    "x-babyshare-device-id": identity.deviceId,
    "x-babyshare-device-token": identity.deviceToken,
    Origin: baseUrl,
  };
}

async function announceLanDevice(identity, sessionCookie) {
  const response = await fetchApp("/api/lan/presence", {
    body: JSON.stringify(identity),
    headers: { "Content-Type": "application/json", ...(sessionCookie ? { Cookie: sessionCookie } : {}), Origin: baseUrl },
    method: "POST",
  });
  assert.equal(response.status, 200);
}

test.before(async () => {
  await Promise.all([
    makeEncryptedFile("alice", "alice-secret.enc", "alice-only"),
    makeEncryptedFile("alice", "expired.enc", "no-longer-available"),
    makeEncryptedFile("alice", "protected.enc", "protected-content"),
    makeEncryptedFile("bob", "bob-secret.enc", "bob-only"),
  ]);
  const interruptedUpload = path.join(testDataDir, "uploads", "tmp", "interrupted-upload");
  const interruptedLanUpload = path.join(testDataDir, "uploads", "lan-tmp", "interrupted-lan-upload");
  fs.mkdirSync(path.dirname(interruptedUpload), { recursive: true });
  fs.mkdirSync(path.dirname(interruptedLanUpload), { recursive: true });
  fs.writeFileSync(interruptedUpload, "plaintext fragment");
  fs.writeFileSync(interruptedLanUpload, "plaintext fragment");
  server = http.createServer(createApp());
  assert.equal(fs.existsSync(interruptedUpload), false);
  assert.equal(fs.existsSync(interruptedLanUpload), false);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

test.after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await fs.promises.rm(testDataDir, { recursive: true, force: true });
});

test("an authenticated user cannot download another user's private file", async () => {
  const cookie = await login("alice", "alice-password-123");
  const response = await fetchApp("/download/bob/bob-secret.enc", { headers: { Cookie: cookie } });
  assert.equal(response.status, 403);
});

test("expired user shares are rejected at request time", async () => {
  const realNow = Date.now;
  Date.now = () => realNow() + 120_000;
  try {
    const response = await fetchApp("/secure-download/alice/expired.enc");
    assert.equal(response.status, 410);
  } finally {
    Date.now = realNow;
  }
});

test("password-protected shares display a prompt and serve only after validation", async () => {
  const prompt = await fetchApp("/secure-download/alice/protected.enc");
  assert.equal(prompt.status, 200);
  assert.match(await prompt.text(), /Password required/);

  const rejected = await fetchApp("/secure-download/alice/protected.enc", {
    body: new URLSearchParams({ action: "download", password: "wrong-password" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
  });
  assert.equal(rejected.status, 401);

  const accepted = await fetchApp("/secure-download/alice/protected.enc", {
    body: new URLSearchParams({ action: "download", password: "share-password-123" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.headers.get("cache-control"), "private, no-store, max-age=0");
  assert.equal(await accepted.text(), "protected-content");
});

test("QR share links download passwordless files and protect password-gated files", async () => {
  const passwordless = await createGuestShare();
  const passwordlessToken = new URL(passwordless.link).searchParams.get("token");
  assert.ok(passwordlessToken);

  const directDownload = await fetchApp(`/guest-download?token=${passwordlessToken}&action=download`);
  assert.equal(directDownload.status, 200);
  assert.match(directDownload.headers.get("content-disposition") || "", /attachment/i);
  assert.equal(await directDownload.text(), "iPhone QR transfer");

  const photo = await createGuestShare({
    contents: Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL8mQAAAABJRU5ErkJggg==", "base64"),
    filename: "phone-photo.png",
    type: "image/png",
  });
  const photoToken = new URL(photo.link).searchParams.get("token");
  assert.ok(photoToken);

  const photoPreview = await fetchApp(`/guest-download?token=${photoToken}&action=preview`);
  assert.equal(photoPreview.status, 200);
  assert.match(photoPreview.headers.get("content-disposition") || "", /inline/i);
  assert.equal(photoPreview.headers.get("content-type"), "image/png");

  const protectedShare = await createGuestShare({ password: "1234" });
  const protectedToken = new URL(protectedShare.link).searchParams.get("token");
  assert.ok(protectedToken);

  const passwordPrompt = await fetchApp(`/guest-view?token=${protectedToken}`);
  assert.equal(passwordPrompt.status, 200);
  assert.match(await passwordPrompt.text(), /Password required/);

  const preview = await fetchApp("/guest-login", {
    body: new URLSearchParams({ action: "preview", password: "1234", token: protectedToken }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
  });
  assert.equal(preview.status, 200);
  assert.match(preview.headers.get("content-disposition") || "", /inline/i);
  assert.equal(await preview.text(), "iPhone QR transfer");
});

test("registration blocks traversal usernames and state changes require a same-origin request", async () => {
  const traversal = await fetchApp("/register", {
    body: new URLSearchParams({ password: "valid-password-123", username: "../../escape" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
  });
  assert.equal(traversal.status, 400);

  const shortPassword = await fetchApp("/register", {
    body: new URLSearchParams({ password: "123", username: "shortpass" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
  });
  assert.equal(shortPassword.status, 400);

  const minimumPassword = await fetchApp("/register", {
    body: new URLSearchParams({ password: "1234", username: "fourpass" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
    redirect: "manual",
  });
  assert.equal(minimumPassword.status, 302);

  const crossOrigin = await fetchApp("/register", {
    body: new URLSearchParams({ password: "valid-password-123", username: "newperson" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://attacker.invalid" },
    method: "POST",
  });
  assert.equal(crossOrigin.status, 403);
});

test("CORS admits only the configured frontend origin and allows device credential headers", async () => {
  const preflight = await fetchApp("/api/lan/devices", {
    headers: {
      "Access-Control-Request-Headers": "content-type,x-babyshare-device-id,x-babyshare-device-token",
      "Access-Control-Request-Method": "GET",
      Origin: "http://localhost:3000",
    },
    method: "OPTIONS",
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("access-control-allow-origin"), "http://localhost:3000");
  assert.equal(preflight.headers.get("access-control-allow-credentials"), "true");
  assert.match(preflight.headers.get("access-control-allow-headers") || "", /x-babyshare-device-token/i);

  const rejected = await fetchApp("/api/lan/devices", {
    headers: { Origin: "https://attacker.invalid" },
    method: "OPTIONS",
  });
  assert.equal(rejected.status, 403);
});

test("LAN polling keeps a separate request budget for each active device", async () => {
  const first = lanIdentity();
  const second = lanIdentity();
  await announceLanDevice(first);
  await announceLanDevice(second);

  for (let index = 0; index < 100; index += 1) {
    const firstPoll = await fetchApp("/api/lan/devices", { headers: lanHeaders(first, false) });
    const secondPoll = await fetchApp("/api/lan/devices", { headers: lanHeaders(second, false) });
    assert.equal(firstPoll.status, 200);
    assert.equal(secondPoll.status, 200);
  }
});

test("an active LAN chat remains available while both participants stay online", async () => {
  const sender = lanIdentity();
  const recipient = lanIdentity();
  await announceLanDevice(sender);
  await announceLanDevice(recipient);

  const requested = await fetchApp("/api/lan/chats/request", {
    body: JSON.stringify({ recipientId: recipient.deviceId }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(requested.status, 201);
  const chat = (await requested.json()).chat;
  assert.equal(chat.status, "active");

  const realNow = Date.now;
  Date.now = () => realNow() + (31 * 60 * 1000);
  try {
    await announceLanDevice(sender);
    await announceLanDevice(recipient);
    const chats = await fetchApp("/api/lan/chats", { headers: lanHeaders(sender, false) });
    assert.equal(chats.status, 200);
    assert.equal((await chats.json()).chats.find((item) => item.id === chat.id)?.status, "active");
  } finally {
    Date.now = realNow;
  }
});

test("LAN chat and recipient-approved direct transfers are available immediately and erased after use", async () => {
  const sender = lanIdentity();
  const recipient = lanIdentity();
  await announceLanDevice(sender);
  await announceLanDevice(recipient);

  const devices = await fetchApp("/api/lan/devices", { headers: lanHeaders(sender, false) });
  assert.equal(devices.status, 200);
  const listedRecipient = (await devices.json()).devices.find((device) => device.id === recipient.deviceId);
  assert.deepEqual(listedRecipient, {
    deviceName: "Test browser device",
    displayName: "Guest",
    id: recipient.deviceId,
    online: true,
    platform: "Test browser",
  });
  assert.equal(Object.hasOwn(listedRecipient, "ip"), false);

  const chatRequested = await fetchApp("/api/lan/chats/request", {
    body: JSON.stringify({ recipientId: recipient.deviceId }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(chatRequested.status, 201);
  const chat = (await chatRequested.json()).chat;
  assert.equal(chat.status, "active");

  const messageSent = await fetchApp(`/api/lan/chats/${chat.id}/messages`, {
    body: JSON.stringify({ text: "This message must disappear when chat ends." }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(messageSent.status, 201);

  const recipientChats = await fetchApp("/api/lan/chats", { headers: lanHeaders(recipient, false) });
  const recipientChat = (await recipientChats.json()).chats.find((item) => item.id === chat.id);
  assert.equal(recipientChat.messages[0].text, "This message must disappear when chat ends.");

  const chatEnded = await fetchApp(`/api/lan/chats/${chat.id}/end`, {
    body: JSON.stringify({}),
    headers: lanHeaders(recipient),
    method: "POST",
  });
  assert.equal(chatEnded.status, 204);
  const erasedChats = await fetchApp("/api/lan/chats", { headers: lanHeaders(sender, false) });
  assert.deepEqual((await erasedChats.json()).chats, []);

  const signalSent = await fetchApp("/api/lan/signals", {
    body: JSON.stringify({
      recipientId: recipient.deviceId,
      signal: { sessionId: "nearby-session-123", sdp: "offer-data", type: "offer" },
    }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(signalSent.status, 202);
  const recipientSignals = await fetchApp("/api/lan/signals", { headers: lanHeaders(recipient, false) });
  assert.equal(recipientSignals.status, 200);
  const deliveredSignals = (await recipientSignals.json()).signals;
  assert.equal(deliveredSignals.length, 1);
  assert.equal(deliveredSignals[0].senderId, sender.deviceId);
  assert.equal(deliveredSignals[0].signal.type, "offer");
  const consumedSignals = await fetchApp("/api/lan/signals", { headers: lanHeaders(recipient, false) });
  assert.deepEqual((await consumedSignals.json()).signals, []);

  const requested = await fetchApp("/api/lan/transfers/request", {
    body: JSON.stringify({
      files: [{ name: "nearby.txt", size: 20 }],
      recipientId: recipient.deviceId,
    }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(requested.status, 201);
  const transfer = (await requested.json()).transfers[0];
  assert.equal(transfer.status, "pending");

  const unauthorizedDownload = await fetchApp(`/api/lan/transfers/${transfer.id}/download`);
  assert.equal(unauthorizedDownload.status, 403);

  const accepted = await fetchApp(`/api/lan/transfers/${transfer.id}/accept`, {
    body: JSON.stringify({}),
    headers: lanHeaders(recipient),
    method: "POST",
  });
  assert.equal(accepted.status, 200);

  const content = new FormData();
  content.append("file", new Blob(["nearby transfer file"]), "nearby.txt");
  const uploaded = await fetchApp(`/api/lan/transfers/${transfer.id}/content`, {
    body: content,
    headers: lanHeaders(sender, false),
    method: "POST",
  });
  assert.equal(uploaded.status, 201);
  assert.equal((await uploaded.json()).transfer.status, "ready");

  const downloadPath = `/api/lan/transfers/${transfer.id}/download?deviceId=${recipient.deviceId}&deviceToken=${recipient.deviceToken}`;
  const download = await fetchApp(downloadPath);
  assert.equal(download.status, 200);
  assert.equal(await download.text(), "nearby transfer file");
  const consumed = await fetchApp(downloadPath);
  assert.equal(consumed.status, 404);
});

test("Nearby Users presents active signed-in users and guests without network addresses", async () => {
  const viewer = lanIdentity();
  const signedInDevice = lanIdentity();
  await announceLanDevice(viewer);
  const aliceSession = await login("alice", "alice-password-123");
  await announceLanDevice(signedInDevice, aliceSession);

  const devices = await fetchApp("/api/lan/devices", { headers: lanHeaders(viewer, false) });
  assert.equal(devices.status, 200);
  const alice = (await devices.json()).devices.find((device) => device.id === signedInDevice.deviceId);
  assert.deepEqual(alice, {
    deviceName: "Test browser device",
    displayName: "alice",
    id: signedInDevice.deviceId,
    online: true,
    platform: "Test browser",
  });
  assert.equal(Object.hasOwn(alice, "ip"), false);
  assert.equal(Object.hasOwn(alice, "scope"), false);
});

test("recipient-approved peer transfers keep file bytes off the BabyShare server", async () => {
  const sender = lanIdentity();
  const recipient = lanIdentity();
  await announceLanDevice(sender);
  await announceLanDevice(recipient);

  const requested = await fetchApp("/api/lan/transfers/request", {
    body: JSON.stringify({ files: [{ name: "direct.txt", size: 17 }], recipientId: recipient.deviceId }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(requested.status, 201);
  const transfer = (await requested.json()).transfers[0];
  assert.equal(transfer.transport, "peer");

  const accepted = await fetchApp(`/api/lan/transfers/${transfer.id}/accept`, {
    body: JSON.stringify({}),
    headers: lanHeaders(recipient),
    method: "POST",
  });
  assert.equal(accepted.status, 200);

  const started = await fetchApp(`/api/lan/transfers/${transfer.id}/peer-start`, {
    body: JSON.stringify({}),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(started.status, 200);
  assert.equal((await started.json()).transfer.status, "receiving");

  const progressed = await fetchApp(`/api/lan/transfers/${transfer.id}/peer-progress`, {
    body: JSON.stringify({ bytesTransferred: 17 }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(progressed.status, 200);

  const completed = await fetchApp(`/api/lan/transfers/${transfer.id}/peer-complete`, {
    body: JSON.stringify({}),
    headers: lanHeaders(recipient),
    method: "POST",
  });
  assert.equal(completed.status, 200);
  assert.equal((await completed.json()).transfer.status, "ready");
  assert.equal(fs.readdirSync(path.join(testDataDir, "uploads", "lan")).length, 0);

  const consumed = await fetchApp(`/api/lan/transfers/${transfer.id}/peer-consume`, {
    body: JSON.stringify({}),
    headers: lanHeaders(recipient),
    method: "POST",
  });
  assert.equal(consumed.status, 204);
});

test("LAN transfer requests are capped before a device can flood a recipient", async () => {
  const sender = lanIdentity();
  const recipient = lanIdentity();
  await announceLanDevice(sender);
  await announceLanDevice(recipient);

  const firstBatch = await fetchApp("/api/lan/transfers/request", {
    body: JSON.stringify({
      files: Array.from({ length: 20 }, (_, index) => ({ name: `file-${index}.txt`, size: 1 })),
      recipientId: recipient.deviceId,
    }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(firstBatch.status, 201);

  const overflow = await fetchApp("/api/lan/transfers/request", {
    body: JSON.stringify({ files: [{ name: "one-too-many.txt", size: 1 }], recipientId: recipient.deviceId }),
    headers: lanHeaders(sender),
    method: "POST",
  });
  assert.equal(overflow.status, 400);
  assert.equal((await overflow.json()).error, "transfer_limit_reached");
});
