// JSON-backed storage for users and share metadata.
const fs = require("fs");
const path = require("path");
const { ROOT_DIR } = require("../config");

// File paths for persisted state.
const USERS_FILE = path.join(ROOT_DIR, "users.json");
const SHARES_FILE = path.join(ROOT_DIR, "shares.json");

// Read users from disk (fallback to default admin).
function loadUsers() {
  if (fs.existsSync(USERS_FILE)) {
    return JSON.parse(fs.readFileSync(USERS_FILE));
  }
  return { admin: "admin123" };
}

// Read shares from disk (empty on first run).
function loadShares() {
  if (fs.existsSync(SHARES_FILE)) {
    return JSON.parse(fs.readFileSync(SHARES_FILE));
  }
  return { users: {}, guests: {} };
}

// Persist users to disk.
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Persist shares to disk.
function saveShares(shares) {
  fs.writeFileSync(SHARES_FILE, JSON.stringify(shares, null, 2));
}

module.exports = {
  USERS_FILE,
  SHARES_FILE,
  loadUsers,
  loadShares,
  saveUsers,
  saveShares,
};
