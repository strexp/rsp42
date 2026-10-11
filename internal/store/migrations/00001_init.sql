-- +goose Up
-- rsp42 schema. The project has no legacy/back-compat requirements, so this is
-- a single, current-schema migration.

-- SM-DP+ profile inventory.
CREATE TABLE IF NOT EXISTS profiles (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    iccid             TEXT    NOT NULL UNIQUE,
    imsi              TEXT,
    profile_type      TEXT,
    eid               TEXT,
    state             TEXT    NOT NULL,
    matching_id       TEXT    UNIQUE,
    cc_hash           BLOB,
    cc_required       INTEGER NOT NULL DEFAULT 0,
    smds_address      TEXT,
    release_flag      INTEGER NOT NULL DEFAULT 0,
    download_attempts INTEGER NOT NULL DEFAULT 0,
    cc_attempts       INTEGER NOT NULL DEFAULT 0,
    upp_template      TEXT,
    personalization   TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    installed_at      INTEGER,
    error_reason      TEXT
);
CREATE INDEX IF NOT EXISTS idx_profiles_iccid       ON profiles(iccid);
CREATE INDEX IF NOT EXISTS idx_profiles_matching_id ON profiles(matching_id);
CREATE INDEX IF NOT EXISTS idx_profiles_eid         ON profiles(eid);

-- ES2+ order audit.
CREATE TABLE IF NOT EXISTS orders (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    iccid         TEXT,
    eid           TEXT,
    matching_id   TEXT,
    action        TEXT NOT NULL,
    request_json  TEXT,
    result_json   TEXT,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_iccid ON orders(iccid);

-- ES9+/ES11 RSP sessions (shared by SM-DP+ and SM-DS databases).
CREATE TABLE IF NOT EXISTS sessions (
    transaction_id   TEXT PRIMARY KEY,
    state            TEXT NOT NULL,
    server_challenge BLOB,
    server_signed1   BLOB,
    smdp_signature2  BLOB,
    ci_cert_id       BLOB,
    eid              TEXT,
    euicc_cert       BLOB,
    eum_cert         BLOB,
    euicc_otpk       BLOB,
    smdp_ot_sk       BLOB,
    host_id          BLOB,
    shared_secret    BLOB,
    profile_id       INTEGER,
    cc_hash          BLOB,
    cc_required      INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Received notifications.
CREATE TABLE IF NOT EXISTS notifications (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    eid               TEXT,
    seq_number        INTEGER,
    operation         TEXT,
    iccid             TEXT,
    transaction_id    TEXT,
    final_result_json TEXT,
    signature_ok      INTEGER NOT NULL DEFAULT 0,
    received_at       INTEGER NOT NULL,
    processed         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_notifications_eid_seq ON notifications(eid, seq_number);

-- SM-DP+ event registrations (for later ES12 deletion).
CREATE TABLE IF NOT EXISTS smds_registrations (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    eid                  TEXT NOT NULL,
    event_id             TEXT NOT NULL,
    rsp_server_address   TEXT,
    forwarding_indicator INTEGER NOT NULL DEFAULT 0,
    registered_at        INTEGER NOT NULL,
    deleted_at           INTEGER
);
CREATE INDEX IF NOT EXISTS idx_smds_registrations_eid ON smds_registrations(eid);

-- Outbound ES2+ callbacks.
CREATE TABLE IF NOT EXISTS es2p_callbacks (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    url                   TEXT NOT NULL,
    payload_json          TEXT,
    notification_point_id INTEGER,
    status                TEXT NOT NULL DEFAULT 'pending',
    attempts              INTEGER NOT NULL DEFAULT 0,
    next_retry_at         INTEGER,
    response              TEXT,
    created_at            INTEGER NOT NULL
);

-- Structured audit log (shared by SM-DP+ and SM-DS databases).
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    actor       TEXT,
    interface   TEXT,
    function    TEXT,
    subject     TEXT,
    outcome     TEXT,
    status_code TEXT,
    remote_addr TEXT,
    detail_json TEXT
);

-- SM-DS event records.
CREATE TABLE IF NOT EXISTS events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    eid                  TEXT    NOT NULL,
    event_id             TEXT    NOT NULL,
    rsp_server_address   TEXT    NOT NULL,
    caller_oid           TEXT    NOT NULL,
    forwarding_indicator INTEGER NOT NULL DEFAULT 0,
    cascaded             INTEGER NOT NULL DEFAULT 0,
    root_event_id        TEXT,
    registered_at        INTEGER NOT NULL,
    expires_at           INTEGER,
    deleted_at           INTEGER,
    UNIQUE (eid, event_id, caller_oid)
);
CREATE INDEX IF NOT EXISTS idx_events_eid ON events(eid);

-- +goose Down
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS es2p_callbacks;
DROP TABLE IF EXISTS smds_registrations;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS profiles;
