-- BabyShare stores only the temporary lookup needed for manual QR pairing.
-- It contains no file data, file URL, or encrypted file payload.
CREATE TABLE IF NOT EXISTS qr_pair_codes (
  code TEXT PRIMARY KEY,
  pair_token TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS qr_pair_codes_expiry_idx ON qr_pair_codes(expires_at);
