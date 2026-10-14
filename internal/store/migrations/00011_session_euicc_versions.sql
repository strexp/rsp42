-- +goose Up
-- N11/N12: persist the eUICC's advertised SAIP versions with the session.
--
-- The eUICC declares profileVersion (and, since SGP.22 v2.7 §5.7.6, an optional
-- additionalEuiccProfilePackageVersions) inside EuiccSigned1, which is only
-- visible while AuthenticateClient runs. The template fallback check happens
-- later, at GetBoundProfilePackage -> loadUPP, so the version set has to survive
-- on the session row.
--
-- euicc_profile_version: the base profileVersion, canonical "<major>.<minor>".
-- euicc_supported_versions: JSON array of every supported "<major>.<minor>"
--   (profileVersion plus the additional list).
-- uicc_capability: the raw uiccCapability BIT STRING content, hex encoded.
ALTER TABLE sessions ADD COLUMN euicc_profile_version TEXT;
ALTER TABLE sessions ADD COLUMN euicc_supported_versions TEXT;
ALTER TABLE sessions ADD COLUMN uicc_capability TEXT;

-- +goose Down
ALTER TABLE sessions DROP COLUMN uicc_capability;
ALTER TABLE sessions DROP COLUMN euicc_supported_versions;
ALTER TABLE sessions DROP COLUMN euicc_profile_version;
