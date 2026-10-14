-- +goose Up
-- UPP template version history: every replacement of a (tenant, name) template
-- archives the previous bytes so a template can be rolled back (G18).
CREATE TABLE IF NOT EXISTS upp_template_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT,
    name        TEXT    NOT NULL,
    version_no  INTEGER NOT NULL,
    saip_major  INTEGER NOT NULL,
    saip_minor  INTEGER NOT NULL,
    sha256      TEXT    NOT NULL,
    bytes       BLOB    NOT NULL,
    note        TEXT,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_upp_versions_scope
    ON upp_template_versions(COALESCE(tenant_id,''), name, version_no DESC);

-- +goose Down
DROP TABLE IF EXISTS upp_template_versions;
