package config

import (
	"fmt"

	"rsp42/internal/saipver"
)

// Per-section validation. Config.Validate orchestrates these; keeping them on
// the sections lets a command validate only what it uses (e.g. a database-only
// admin command validates the store sections, not the server certificates),
// instead of every caller having to validate the whole object.

// Validate checks the log settings.
func (l LogConfig) Validate() error {
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q invalid (want debug|info|warn|error)", l.Level)
	}
	switch l.Format {
	case "json", "text":
	default:
		return fmt.Errorf("log.format %q invalid (want json|text)", l.Format)
	}
	return nil
}

// Validate checks the KMS provider name. Key material itself is validated by
// validateKEKConfig, which is only meaningful for a process that opens keys.
func (k KMSConfig) Validate() error {
	switch k.Provider {
	case "file":
	default:
		return fmt.Errorf("kms.provider %q invalid (want file)", k.Provider)
	}
	return nil
}

// Validate checks the UPP template registry and personalization settings,
// including the deliberate SQLite-only decision
// (docs/esim42-integration-gaps.md §8.4 decision 7).
func (p ProfilesConfig) Validate() error {
	switch p.Repository {
	case "sqlite":
	case "":
		return fmt.Errorf("profiles.repository must be set to \"sqlite\"")
	default:
		return fmt.Errorf("profiles.repository %q is not supported: rsp42 only implements SQLite "+
			"(PostgreSQL and multi-replica deployments are deliberate non-goals, "+
			"see docs/esim42-integration-gaps.md §8.4)", p.Repository)
	}
	for i, raw := range p.AllowedSAIPVersions {
		if _, err := saipver.Parse(raw); err != nil {
			return fmt.Errorf("profiles.allowed_saip_versions[%d]: %w", i, err)
		}
	}
	if p.Personalization.ReserveTTL < 0 {
		return fmt.Errorf("profiles.personalization.reserve_ttl must be >= 0")
	}
	if p.Personalization.IdempotencyTTL < 0 {
		return fmt.Errorf("profiles.personalization.idempotency_ttl must be >= 0")
	}
	for _, id := range p.PPRIds {
		if id < 0 || id > 2 {
			return fmt.Errorf("profiles.ppr_ids entry %d out of range [0,2]", id)
		}
	}
	return nil
}
