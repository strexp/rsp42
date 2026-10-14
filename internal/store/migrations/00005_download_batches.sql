-- +goose Up
-- Download batches (lists of profiles/orders managed together).
CREATE TABLE IF NOT EXISTS download_batches (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT,
    profile_type TEXT,
    state        TEXT    NOT NULL DEFAULT 'Open',
    total        INTEGER NOT NULL DEFAULT 0,
    note         TEXT,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

ALTER TABLE profiles ADD COLUMN batch_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_profiles_batch ON profiles(batch_id);

-- +goose Down
ALTER TABLE profiles DROP COLUMN batch_id;
DROP TABLE IF EXISTS download_batches;
