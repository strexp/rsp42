-- +goose Up
-- 00008 added iccid_pool.imsi for an operator "SIM pair" (号卡对) import that was
-- never wired up: no statement reads or writes the column, and the credentials
-- pool keys IMSI on personalization.imsi instead. Drop it so the schema matches
-- the code (it was the last unreferenced column on the table).
ALTER TABLE iccid_pool DROP COLUMN imsi;

-- +goose Down
ALTER TABLE iccid_pool ADD COLUMN imsi TEXT;
