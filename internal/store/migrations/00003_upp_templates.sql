-- +goose Up
-- UPP (SAIP profile package) template registry. The SM-DP+ reads templates from
-- this table at download time; `upp_dir` is only an import source (see
-- `rsp42 admin upp import`).
CREATE TABLE IF NOT EXISTS upp_templates (
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
CREATE INDEX IF NOT EXISTS idx_upp_templates_version ON upp_templates(saip_major, saip_minor);

-- +goose Down
DROP TABLE IF EXISTS upp_templates;
