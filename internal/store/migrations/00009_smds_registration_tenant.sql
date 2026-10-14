-- +goose Up
-- ES12 correlation: the tenant an SM-DP+ registered an event for, carried out of
-- band in a request header (SGP.22 §6.2 allows additional header fields).
ALTER TABLE smds_registrations ADD COLUMN tenant_id TEXT;

-- +goose Down
ALTER TABLE smds_registrations DROP COLUMN tenant_id;
