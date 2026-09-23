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

test.before(async () => {
  await Promise.all([
    makeEncryptedFile("alice", "alice-secret.enc", "alice-only"),
    makeEncryptedFile("alice", "expired.enc", "no-longer-available"),
    makeEncryptedFile("alice", "protected.enc", "protected-content"),
    makeEncryptedFile("bob", "bob-secret.enc", "bob-only"),
  ]);
  server = http.createServer(createApp());
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
  assert.equal(await accepted.text(), "protected-content");
});

test("registration blocks traversal usernames and state changes require a same-origin request", async () => {
  const traversal = await fetchApp("/register", {
    body: new URLSearchParams({ password: "valid-password-123", username: "../../escape" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: baseUrl },
    method: "POST",
  });
  assert.equal(traversal.status, 400);

  const crossOrigin = await fetchApp("/register", {
    body: new URLSearchParams({ password: "valid-password-123", username: "newperson" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://attacker.invalid" },
    method: "POST",
  });
  assert.equal(crossOrigin.status, 403);
});
