-- +goose Up
-- esim42 integration: tenant (carrier) dimension, external references,
-- idempotency and ICCID pool hardening.
--
-- Implementation note: docs/esim42-integration-gaps.md §4 suggested folding
-- these changes into 00001_init.sql. Migrations 00002..00006 already exist in
-- this tree, so folding would mean squashing the whole history (and would make
-- an already-migrated database fail goose's version check). This migration is
-- therefore additive instead; the project keeps its "no back-compat code"
-- stance, it only keeps the migration history append-only.

-- Tenant (carrier) registry. `id` is esim42's Carrier primary key (no second
-- mapping layer, see §8.1 decision 1).
CREATE TABLE IF NOT EXISTS tenants (
    id             TEXT PRIMARY KEY,
    name           TEXT    NOT NULL,
    status         TEXT    NOT NULL DEFAULT 'active',
    template_quota INTEGER,          -- NULL = unlimited
    profile_quota  INTEGER,          -- NULL = unlimited
    default_upp    TEXT,             -- tenant default UPP template name
    callback_url   TEXT,             -- per-tenant ES2+ progress callback (NULL = global)
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
);

-- Ownership columns. NULL means "platform global" (the global system templates
-- of module D, and the platform-default tenant of an unmapped ES2+ caller).
ALTER TABLE profiles         ADD COLUMN tenant_id TEXT;
ALTER TABLE profiles         ADD COLUMN external_ref TEXT;
ALTER TABLE download_batches ADD COLUMN tenant_id TEXT;
ALTER TABLE personalization  ADD COLUMN tenant_id TEXT;
ALTER TABLE iccid_ranges     ADD COLUMN tenant_id TEXT;
ALTER TABLE iccid_pool       ADD COLUMN tenant_id TEXT;
ALTER TABLE iccid_pool       ADD COLUMN reserved_until INTEGER;
ALTER TABLE iccid_pool       ADD COLUMN reference TEXT;
ALTER TABLE iccid_pool       ADD COLUMN profile_id INTEGER;
ALTER TABLE audit_log        ADD COLUMN tenant_id TEXT;
ALTER TABLE orders           ADD COLUMN tenant_id TEXT;
ALTER TABLE events           ADD COLUMN tenant_id TEXT;
ALTER TABLE events           ADD COLUMN iccid TEXT;
ALTER TABLE events           ADD COLUMN matching_id TEXT;

CREATE INDEX IF NOT EXISTS idx_profiles_tenant   ON profiles(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_orders_tenant     ON orders(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_batches_tenant    ON download_batches(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_pool_tenant       ON iccid_pool(tenant_id, state);
CREATE INDEX IF NOT EXISTS idx_perso_tenant      ON personalization(tenant_id, iccid);
CREATE INDEX IF NOT EXISTS idx_ranges_tenant     ON iccid_ranges(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_tenant      ON audit_log(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_tenant     ON events(tenant_id, registered_at);

-- external_ref is unique per tenant (NULL tenant = platform default).
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_extref
    ON profiles(COALESCE(tenant_id, ''), external_ref) WHERE external_ref IS NOT NULL;

-- upp_templates.name was globally UNIQUE, which prevents two tenants from each
-- having a template called "default". SQLite cannot drop an inline UNIQUE
-- constraint, so the table is rebuilt. A COALESCE() expression index is used so
-- that a NULL tenant_id (global template) is still name-unique.
CREATE TABLE upp_templates_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    tenant_id   TEXT,
    saip_major  INTEGER NOT NULL,
    saip_minor  INTEGER NOT NULL,
    sha256      TEXT    NOT NULL,
    bytes       BLOB    NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
INSERT INTO upp_templates_new (id, name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at)
    SELECT id, name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at FROM upp_templates;
DROP TABLE upp_templates;
ALTER TABLE upp_templates_new RENAME TO upp_templates;
CREATE UNIQUE INDEX IF NOT EXISTS idx_upp_tenant_name ON upp_templates(COALESCE(tenant_id, ''), name);
CREATE INDEX IF NOT EXISTS idx_upp_templates_version ON upp_templates(saip_major, saip_minor);

-- Idempotent replay of write endpoints (only for functions without a standard
-- resend semantic; see G5).
CREATE TABLE IF NOT EXISTS idempotency (
    key           TEXT    NOT NULL,
    endpoint      TEXT    NOT NULL,
    tenant_id     TEXT,
    request_hash  TEXT    NOT NULL,
    status        INTEGER NOT NULL,
    response_json TEXT,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (key, endpoint)
);
CREATE INDEX IF NOT EXISTS idx_idempotency_created ON idempotency(created_at);

-- +goose Down
DROP TABLE IF EXISTS idempotency;

CREATE TABLE upp_templates_old (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    saip_major  INTEGER NOT NULL,
    saip_minor  INTEGER NOT NULL,
    sha256      TEXT    NOT NULL,
    bytes       BLOB    NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
INSERT INTO upp_templates_old (id, name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at)
    SELECT id, name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at FROM upp_templates WHERE tenant_id IS NULL;
DROP TABLE upp_templates;
ALTER TABLE upp_templates_old RENAME TO upp_templates;

DROP INDEX IF EXISTS idx_events_tenant;
DROP INDEX IF EXISTS idx_audit_tenant;
DROP INDEX IF EXISTS idx_ranges_tenant;
DROP INDEX IF EXISTS idx_perso_tenant;
DROP INDEX IF EXISTS idx_pool_tenant;
DROP INDEX IF EXISTS idx_batches_tenant;
DROP INDEX IF EXISTS idx_orders_tenant;
DROP INDEX IF EXISTS idx_profiles_tenant;
DROP INDEX IF EXISTS idx_profiles_extref;
ALTER TABLE events           DROP COLUMN matching_id;
ALTER TABLE events           DROP COLUMN iccid;
ALTER TABLE events           DROP COLUMN tenant_id;
ALTER TABLE orders           DROP COLUMN tenant_id;
ALTER TABLE audit_log        DROP COLUMN tenant_id;
ALTER TABLE iccid_pool       DROP COLUMN profile_id;
ALTER TABLE iccid_pool       DROP COLUMN reference;
ALTER TABLE iccid_pool       DROP COLUMN reserved_until;
ALTER TABLE iccid_pool       DROP COLUMN tenant_id;
ALTER TABLE iccid_ranges     DROP COLUMN tenant_id;
ALTER TABLE personalization  DROP COLUMN tenant_id;
ALTER TABLE download_batches DROP COLUMN tenant_id;
ALTER TABLE profiles         DROP COLUMN external_ref;
ALTER TABLE profiles         DROP COLUMN tenant_id;
DROP TABLE IF EXISTS tenants;
