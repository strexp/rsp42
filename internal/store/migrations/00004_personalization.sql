-- +goose Up
-- Per-ICCID SAIP personalization values. The SM-DP+ resolves a profile's
-- personalization from this table at download time; the configured
-- personalization source (CSV/file) is only an import source. Sensitive fields
-- (k, opc) are stored encrypted with the KMS key-encryption key.
CREATE TABLE IF NOT EXISTS personalization (
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

-- +goose Down
DROP TABLE IF EXISTS personalization;
