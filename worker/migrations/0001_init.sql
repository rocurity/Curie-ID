-- Curie ID schema for Cloudflare D1. Times are Unix milliseconds.
-- Not yet deployed, so this is the complete initial schema.

CREATE TABLE IF NOT EXISTS users (
  curie_id       TEXT PRIMARY KEY,
  username       TEXT NOT NULL UNIQUE,
  email          TEXT NOT NULL UNIQUE,
  display_name   TEXT NOT NULL,
  date_of_birth  TEXT NOT NULL,
  gender         TEXT,
  password_hash  TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('pending_email', 'active', 'suspended')),
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  sid           TEXT PRIMARY KEY,
  curie_id      TEXT NOT NULL REFERENCES users(curie_id),
  device_id     TEXT,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_by_user ON sessions (curie_id);

CREATE TABLE IF NOT EXISTS devices (
  curie_id   TEXT NOT NULL,
  device_id  TEXT NOT NULL,
  added_at   INTEGER NOT NULL,
  PRIMARY KEY (curie_id, device_id)
);

CREATE TABLE IF NOT EXISTS codes (
  id          TEXT PRIMARY KEY,
  curie_id    TEXT NOT NULL,
  purpose     TEXT NOT NULL,
  device_id   TEXT,
  code_hash   TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  curie_id    TEXT NOT NULL,
  type        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_user ON events (curie_id, created_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  key           TEXT PRIMARY KEY,
  window_start  INTEGER NOT NULL,
  count         INTEGER NOT NULL
);
