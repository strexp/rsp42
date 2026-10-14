-- +goose Up
-- ICCID inventory: operator-imported ranges and the pool of individual ICCIDs.
CREATE TABLE IF NOT EXISTS iccid_ranges (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    start      TEXT    NOT NULL,
    end        TEXT    NOT NULL,
    note       TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS iccid_pool (
    iccid        TEXT PRIMARY KEY,
    state        TEXT    NOT NULL DEFAULT 'available', -- available|allocated|blocked
    range_id     INTEGER,
    eid          TEXT,
    batch_id     INTEGER,
    note         TEXT,
    allocated_at INTEGER,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iccid_pool_state ON iccid_pool(state);
CREATE INDEX IF NOT EXISTS idx_iccid_pool_range ON iccid_pool(range_id);

-- +goose Down
DROP TABLE IF EXISTS iccid_pool;
DROP TABLE IF EXISTS iccid_ranges;
