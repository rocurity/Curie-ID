-- Developer portal: apps registered by developers themselves.
CREATE TABLE IF NOT EXISTS dev_apps (
  client_id          TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  owner_curie_id     TEXT NOT NULL,
  type               TEXT NOT NULL CHECK (type IN ('public', 'confidential')),
  redirect_uris      TEXT NOT NULL,
  client_secret_hash TEXT,
  disabled           INTEGER NOT NULL DEFAULT 0,
  created_at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dev_apps_by_owner ON dev_apps (owner_curie_id);
