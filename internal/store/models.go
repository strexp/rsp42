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
	ID               int64
	ICCID            string
	IMSI             string
	ProfileType      string
	EID              string
	State            ProfileState
	MatchingID       string
	CCHash           []byte // encrypted (AES-256-GCM)
	CCRequired       bool
	SMDSAddress      string
	ReleaseFlag      bool
	DownloadAttempts int
	CCAttempts       int
	UPPTemplate      string
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

// EventRecord is a row of the SM-DS event store (SGP.22 §3.6).
type EventRecord struct {
	ID                  int64
	EID                 string
	EventID             string
	RSPServerAddress    string
	CallerOID           string
	ForwardingIndicator bool
	Cascaded            bool
	RootEventID         string
	RegisteredAt        time.Time
	ExpiresAt           *time.Time
	DeletedAt           *time.Time
}

// Notification is a received notification row.
type Notification struct {
	ID              int64
	EID             string
	SeqNumber       int64
	Operation       string
	ICCID           string
	TransactionID   string
	FinalResultJSON string
	SignatureOK     bool
	ReceivedAt      time.Time
	Processed       bool
}
