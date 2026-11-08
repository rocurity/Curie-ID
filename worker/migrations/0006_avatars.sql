-- Profile pictures: one small square image per account, stored as base64.
CREATE TABLE IF NOT EXISTS avatars (
  curie_id    TEXT PRIMARY KEY,
  mime        TEXT NOT NULL,
  data        TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
);
