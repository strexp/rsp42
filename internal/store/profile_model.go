package store

import "time"

// ProfileState is the SGP.22 profile lifecycle state (SGP.22 §3.1.6 Table 6b).
type ProfileState string

// Profile states.
const (
	StateAvailable   ProfileState = "Available"
	StateAllocated   ProfileState = "Allocated"
	StateLinked      ProfileState = "Linked"
	StateConfirmed   ProfileState = "Confirmed"
	StateReleased    ProfileState = "Released"
	StateDownloaded  ProfileState = "Downloaded"
	StateInstalled   ProfileState = "Installed"
	StateError       ProfileState = "Error"
	StateUnavailable ProfileState = "Unavailable"
)

// Profile is a row of the profile inventory.
type Profile struct {
	ID int64
	// TenantID is the owning carrier; the empty string is the platform default.
	TenantID string
	// ExternalRef is the caller's own identifier for this profile. It is an
	// Admin API convenience field only and is never carried on ES2+.
	ExternalRef string
	ICCID       string
	IMSI        string
	ProfileType string
	EID         string
	State       ProfileState
	MatchingID  string
	// CCHash is SHA-256 of the operator-supplied confirmation code, stored as a
	// plain digest; confirmationHash() mixes it with the TransactionID. It is
	// not encrypted at rest (only Session secrets are).
	CCHash           []byte
	CCRequired       bool
	SMDSAddress      string
	ReleaseFlag      bool
	DownloadAttempts int
	CCAttempts       int
	UPPTemplate      string
	PPRIds           []byte // PprIds BIT STRING content bytes
	BatchID          *int64
	Personalization  string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	InstalledAt      *time.Time
	ErrorReason      string
}

// ProfileName returns a human-readable profile name for metadata.
func (p *Profile) ProfileName() string {
	if p.UPPTemplate != "" {
		return p.UPPTemplate
	}
	return "RSP42 Profile " + p.ICCID
}
