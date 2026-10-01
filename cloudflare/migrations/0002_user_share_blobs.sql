-- Small authenticated shares for the R2-free Worker deployment. The encrypted
-- blob stays under D1's 2 MB per-row limit; larger shares remain available in
-- the local Node runtime or through the existing peer-to-peer transfer flow.
CREATE TABLE IF NOT EXISTS user_shares (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  original_name TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  password_hash TEXT,
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  data BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  uploaded_at INTEGER NOT NULL,
  FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_shares_owner_expiry_idx ON user_shares(username, expires_at);
CREATE INDEX IF NOT EXISTS user_shares_expiry_idx ON user_shares(expires_at);
