-- +goose Up
-- G6/G7: decouple credentials from ICCIDs (credentials pool keyed by IMSI) and
-- add the missing personalization fields (PLMN list, MSISDN, ACC, per-file
-- overrides).

CREATE TABLE personalization_new (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        TEXT,
    -- iccid is NULL for a credentials-pool entry, which is paired with an ICCID
    -- when that ICCID is reserved.
    iccid            TEXT,
    imsi             TEXT,
    k                BLOB,
    opc              BLOB,
    pin1             TEXT,
    puk1             TEXT,
    adm1             TEXT,
    adm2             TEXT,
    spn              TEXT,
    algorithm        TEXT,
    rotation         BLOB,
    xoring           BLOB,
    number_of_keccak INTEGER,
    plmn             TEXT,   -- JSON [{mcc,mnc,act}]
    msisdn           TEXT,
    acc              INTEGER,
    file_patches     TEXT,   -- JSON [{fid,hex}]
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);
INSERT INTO personalization_new
    (tenant_id, iccid, imsi, k, opc, pin1, puk1, adm1, adm2, spn, algorithm,
     rotation, xoring, number_of_keccak, created_at, updated_at)
    SELECT tenant_id, iccid, imsi, k, opc, pin1, puk1, adm1, adm2, spn, algorithm,
           rotation, xoring, number_of_keccak, created_at, updated_at
    FROM personalization;
DROP TABLE personalization;
ALTER TABLE personalization_new RENAME TO personalization;

CREATE UNIQUE INDEX IF NOT EXISTS idx_perso_tenant_iccid
    ON personalization(COALESCE(tenant_id,''), iccid) WHERE iccid IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_perso_tenant_imsi
    ON personalization(COALESCE(tenant_id,''), imsi) WHERE imsi IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_perso_pool ON personalization(COALESCE(tenant_id,''), iccid, imsi);

-- ICCID pool: the IMSI paired with a reserved ICCID (operator "号卡对" imports).
ALTER TABLE iccid_pool ADD COLUMN imsi TEXT;

-- +goose Down
ALTER TABLE iccid_pool DROP COLUMN imsi;
DROP INDEX IF EXISTS idx_perso_pool;
DROP INDEX IF EXISTS idx_perso_tenant_imsi;
DROP INDEX IF EXISTS idx_perso_tenant_iccid;

CREATE TABLE personalization_old (
    iccid            TEXT PRIMARY KEY,
    imsi             TEXT,
    k                BLOB,
    opc              BLOB,
    pin1             TEXT,
    puk1             TEXT,
    adm1             TEXT,
    adm2             TEXT,
    spn              TEXT,
    algorithm        TEXT,
    rotation         BLOB,
    xoring           BLOB,
    number_of_keccak INTEGER,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);
INSERT INTO personalization_old (iccid, imsi, k, opc, pin1, puk1, adm1, adm2, spn, algorithm,
    rotation, xoring, number_of_keccak, created_at, updated_at)
    SELECT iccid, imsi, k, opc, pin1, puk1, adm1, adm2, spn, algorithm,
           rotation, xoring, number_of_keccak, created_at, updated_at
    FROM personalization WHERE iccid IS NOT NULL;
DROP TABLE personalization;
ALTER TABLE personalization_old RENAME TO personalization;
