-- +goose Up
-- The UPP template selected for a session, derived from the eUICC's advertised
-- profile version at AuthenticateClient and consumed at GetBoundProfilePackage.
ALTER TABLE sessions ADD COLUMN upp_template TEXT;
-- Per-profile Profile Policy Rules (PprIds BIT STRING content bytes), set by the
-- operator on the download order.
ALTER TABLE profiles ADD COLUMN ppr_ids BLOB;

-- +goose Down
ALTER TABLE profiles DROP COLUMN ppr_ids;
ALTER TABLE sessions DROP COLUMN upp_template;
