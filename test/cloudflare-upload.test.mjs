import assert from "node:assert/strict";
import test from "node:test";

import worker from "../cloudflare/worker.mjs";

function normalizedSql(value) {
  return value.replace(/\s+/g, " ").trim().toUpperCase();
}

class MemoryStatement {
  constructor(database, sql) {
    this.database = database;
    this.sql = normalizedSql(sql);
    this.values = [];
  }

  bind(...values) {
    this.values = values;
    return this;
  }

  async first() {
    const { rows } = this.database.execute(this.sql, this.values);
    return rows[0] || null;
  }

  async all() {
    const { rows } = this.database.execute(this.sql, this.values);
    return { results: rows };
  }

  async run() {
    const { changes } = this.database.execute(this.sql, this.values);
    return { meta: { changes } };
  }
}

class MemoryD1 {
  constructor() {
    this.sessions = new Map();
    this.shares = new Map();
    this.users = new Map();
  }

  prepare(sql) {
    return new MemoryStatement(this, sql);
  }

  execute(sql, values) {
    if (sql.startsWith("CREATE TABLE IF NOT EXISTS USER_SHARES") || sql.startsWith("CREATE INDEX IF NOT EXISTS USER_SHARES_")) {
      return { changes: 0, rows: [] };
    }
    if (sql === "SELECT USERNAME FROM USERS WHERE USERNAME = ?") {
      const username = values[0];
      return { changes: 0, rows: this.users.has(username) ? [{ username }] : [] };
    }
    if (sql.startsWith("INSERT INTO USERS (USERNAME, PASSWORD_HASH, CREATED_AT) VALUES (?, ?, ?)") && !sql.includes("ON CONFLICT")) {
      const [username, passwordHash, createdAt] = values;
      this.users.set(username, { created_at: createdAt, password_hash: passwordHash, username });
      return { changes: 1, rows: [] };
    }
    if (sql === "SELECT PASSWORD_HASH FROM USERS WHERE USERNAME = ?") {
      const user = this.users.get(values[0]);
      return { changes: 0, rows: user ? [{ password_hash: user.password_hash }] : [] };
    }
    if (sql === "DELETE FROM SESSIONS WHERE USERNAME = ?") {
      const username = values[0];
      const removed = [...this.sessions.values()].filter((session) => session.username === username);
      removed.forEach((session) => this.sessions.delete(session.id));
      return { changes: removed.length, rows: [] };
    }
    if (sql === "INSERT INTO SESSIONS (ID, USERNAME, EXPIRES_AT, CREATED_AT) VALUES (?, ?, ?, ?)") {
      const [id, username, expiresAt, createdAt] = values;
      this.sessions.set(id, { created_at: createdAt, expires_at: expiresAt, id, username });
      return { changes: 1, rows: [] };
    }
    if (sql === "SELECT USERNAME, EXPIRES_AT FROM SESSIONS WHERE ID = ?") {
      const session = this.sessions.get(values[0]);
      return { changes: 0, rows: session ? [{ expires_at: session.expires_at, username: session.username }] : [] };
    }
    if (sql === "DELETE FROM SESSIONS WHERE ID = ?") {
      const changes = this.sessions.delete(values[0]) ? 1 : 0;
      return { changes, rows: [] };
    }
    if (sql.startsWith("INSERT INTO USER_SHARES (ID, USERNAME, ORIGINAL_NAME, LABEL, PASSWORD_HASH, CONTENT_TYPE, SIZE, DATA, EXPIRES_AT, UPLOADED_AT)")) {
      const [id, username, originalName, label, passwordHash, contentType, size, data, expiresAt, uploadedAt] = values;
      this.shares.set(id, {
        content_type: contentType,
        data,
        expires_at: expiresAt,
        id,
        label,
        original_name: originalName,
        password_hash: passwordHash,
        size,
        uploaded_at: uploadedAt,
        username,
      });
      return { changes: 1, rows: [] };
    }
    if (sql.startsWith("SELECT ID, USERNAME, ORIGINAL_NAME, LABEL, PASSWORD_HASH, CONTENT_TYPE, SIZE, DATA, EXPIRES_AT, UPLOADED_AT FROM USER_SHARES WHERE USERNAME = ? AND ID = ?")) {
      const share = this.shares.get(values[1]);
      return { changes: 0, rows: share?.username === values[0] ? [share] : [] };
    }
    if (sql.startsWith("SELECT ID, USERNAME, ORIGINAL_NAME, LABEL, PASSWORD_HASH, EXPIRES_AT, UPLOADED_AT FROM USER_SHARES WHERE EXPIRES_AT > ?")) {
      const rows = [...this.shares.values()]
        .filter((share) => share.expires_at > values[0])
        .sort((left, right) => right.uploaded_at - left.uploaded_at)
        .map(({ data: _data, content_type: _contentType, size: _size, ...share }) => share);
      return { changes: 0, rows };
    }
    if (sql === "DELETE FROM USER_SHARES WHERE ID = ?") {
      const changes = this.shares.delete(values[0]) ? 1 : 0;
      return { changes, rows: [] };
    }
    if (sql === "DELETE FROM SESSIONS WHERE EXPIRES_AT <= ?") {
      const expired = [...this.sessions.values()].filter((session) => session.expires_at <= values[0]);
      expired.forEach((session) => this.sessions.delete(session.id));
      return { changes: expired.length, rows: [] };
    }
    throw new Error(`Unexpected D1 statement: ${sql}`);
  }
}

function workerRequest(path, init = {}) {
  return new Request(`https://babyshare.test${path}`, {
    ...init,
    headers: { Origin: "https://babyshare.test", ...(init.headers || {}) },
  });
}

test("an authenticated Worker session uploads, stores, shares, survives refresh, and deletes a file", async () => {
  const database = new MemoryD1();
  const env = {
    BOOTSTRAP_ADMIN_PASSWORD: "bootstrap-password",
    BOOTSTRAP_ADMIN_USERNAME: "admin",
    DB: database,
    SESSION_SECRET: "test-session-secret-that-is-long-enough-for-encrypted-files",
  };
  const context = { waitUntil() {} };

  const registered = await worker.fetch(workerRequest("/register", {
    body: new URLSearchParams({ password: "alice-password", username: "alice" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    method: "POST",
  }), env, context);
  assert.equal(registered.status, 302);

  const signedIn = await worker.fetch(workerRequest("/login", {
    body: new URLSearchParams({ password: "alice-password", username: "alice" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    method: "POST",
  }), env, context);
  assert.equal(signedIn.status, 302);
  const sessionCookie = signedIn.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(sessionCookie, "login creates a session cookie");

  const uploadForm = new FormData();
  uploadForm.append("files", new Blob(["authenticated upload contents"], { type: "text/plain" }), "regression.txt");
  uploadForm.append("label", "Authenticated regression");
  const uploaded = await worker.fetch(workerRequest("/upload", {
    body: uploadForm,
    headers: { Cookie: sessionCookie },
    method: "POST",
  }), env, context);
  assert.equal(uploaded.status, 201);
  const created = await uploaded.json();
  assert.equal(created.ok, true);
  assert.equal(created.links.length, 1);
  assert.equal(created.links[0].name, "Authenticated regression");
  assert.equal(database.shares.size, 1, "the file is stored in D1");
  assert.notEqual(new TextDecoder().decode(database.shares.values().next().value.data), "authenticated upload contents", "D1 does not hold plaintext file bytes");

  const refreshedSession = await worker.fetch(workerRequest("/api/me", { headers: { Cookie: sessionCookie } }), env, context);
  assert.equal(refreshedSession.status, 200, "the login remains valid after refresh");
  assert.equal((await refreshedSession.json()).user, "alice");

  const listed = await worker.fetch(workerRequest("/api/files", { headers: { Cookie: sessionCookie } }), env, context);
  assert.equal(listed.status, 200);
  const vault = await listed.json();
  assert.equal(vault.files.length, 1);
  assert.equal(vault.files[0].original, "regression.txt");

  const downloaded = await worker.fetch(workerRequest(new URL(created.links[0].url).pathname), env, context);
  assert.equal(downloaded.status, 200);
  assert.match(downloaded.headers.get("content-type") || "", /^text\/plain(?:;|$)/i);
  assert.equal(await downloaded.text(), "authenticated upload contents");

  const deleted = await worker.fetch(workerRequest(`/api/files/alice/${vault.files[0].file}`, {
    headers: { Cookie: sessionCookie },
    method: "DELETE",
  }), env, context);
  assert.equal(deleted.status, 204);
  assert.equal(database.shares.size, 0);
});
