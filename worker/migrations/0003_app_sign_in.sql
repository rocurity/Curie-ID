-- App sign-in: sessions can belong to an app, approved apps are recorded per account,
-- and one-time authorization codes are stored by hash.
ALTER TABLE sessions ADD COLUMN client_id TEXT;

CREATE TABLE IF NOT EXISTS grants (
  curie_id    TEXT NOT NULL,
  client_id   TEXT NOT NULL,
  granted_at  INTEGER NOT NULL,
  PRIMARY KEY (curie_id, client_id)
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash       TEXT PRIMARY KEY,
  curie_id        TEXT NOT NULL,
  client_id       TEXT NOT NULL,
  redirect_uri    TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  expires_at      INTEGER NOT NULL
);
