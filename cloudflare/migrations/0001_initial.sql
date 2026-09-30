CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS user_shares (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  original_name TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  password_hash TEXT,
  expires_at INTEGER NOT NULL,
  uploaded_at INTEGER NOT NULL,
  FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_shares_owner_idx ON user_shares(username, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS user_shares_expiry_idx ON user_shares(expires_at);

CREATE TABLE IF NOT EXISTS guest_shares (
  token TEXT PRIMARY KEY,
  object_key TEXT NOT NULL UNIQUE,
  original_name TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  password_hash TEXT,
  expires_at INTEGER NOT NULL,
  uploaded_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guest_shares_expiry_idx ON guest_shares(expires_at);
