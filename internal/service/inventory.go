package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// sameResend reports whether an existing profile can satisfy a repeated
// downloadOrder (SGP.22 Table 24 NOTE): same tenant, same profile type and the
// same EID, still awaiting download.
func sameResend(p *store.Profile, req AllocateRequest) bool {
	switch p.State {
	case store.StateAllocated, store.StateLinked:
	default:
		return false
	}
	if p.TenantID != req.Tenant {
		return false
	}
	if req.ProfileType != "" && p.ProfileType != req.ProfileType {
		return false
	}
	if req.EID != "" && p.EID != req.EID {
		return false
	}
	return true
}

// ICCIDPool reserves and recycles ICCIDs from an operator-managed pool.
type ICCIDPool interface {
	Reserve(tenant, eid, reference string, ttl time.Duration) (string, error)
	Claim(iccid string, profileID int64) error
	SetState(iccid, state, note string) error
	// State reports a pool entry's state ("available", "allocated", "blocked"),
	// or store.ErrNotFound when the ICCID is not managed by the pool.
	State(iccid string) (string, error)
}

// AllocateRequest parameterizes a profile allocation (ES2+.DownloadOrder or the
// equivalent Admin API call).
type AllocateRequest struct {
	EID string
	// ProfileType is the SGP.22 "content free" operator field. rsp42 interprets
	// "<tenant>/<template>" as a tenant-local template selector (G3).
	ProfileType string
	// ICCID, when non-empty, is used verbatim (SGP.22 §5.3.1 / Table 23).
	ICCID string
	// UPPTemplate optionally pins the SAIP template for this profile.
	UPPTemplate string
	// Tenant is the owning carrier ("" = platform default).
	Tenant string
	// ExternalRef is the caller's own identifier (Admin API convenience field).
	ExternalRef string
	// Reference is the caller's order/claim id, recorded on pooled ICCIDs.
	Reference string
}

// ErrQuotaExceeded indicates that a tenant quota is exhausted.
var ErrQuotaExceeded = errors.New("service: quota exceeded")

// Inventory allocates ICCIDs and creates profile rows for ES2+.DownloadOrder. If
// a Pool is set it is preferred; otherwise an ICCID is generated on demand.
type Inventory struct {
	Profiles ProfileCreator
	// Pool, when set, is the preferred ICCID source.
	Pool ICCIDPool
	// ReserveTTL bounds how long a pool reservation may stay unclaimed. Zero
	// disables expiry.
	ReserveTTL time.Duration
	// ProfileQuota, when set, reports the tenant's profile limit (nil =
	// unlimited). CountProfiles supplies the current usage. Together they
	// enforce tenants.profile_quota (G2/G15); both must be set to take effect.
	ProfileQuota  func(tenant string) (*int, error)
	CountProfiles func(tenant string) (int, error)
	ICCIDPrefix   string
	IMSI          string
}

// checkQuota enforces the tenant profile quota for a new allocation. Resends of
// an existing allocation never reach this check.
func (inv *Inventory) checkQuota(tenant string) error {
	if inv.ProfileQuota == nil || inv.CountProfiles == nil {
		return nil
	}
	limit, err := inv.ProfileQuota(tenant)
	if err != nil {
		return err
	}
	if limit == nil {
		return nil
	}
	used, err := inv.CountProfiles(tenant)
	if err != nil {
		return err
	}
	if used >= *limit {
		return fmt.Errorf("%w: tenant %q profile quota (%d)", ErrQuotaExceeded, tenant, *limit)
	}
	return nil
}

// NewInventory builds an Inventory.
func NewInventory(repo ProfileCreator, iccidPrefix, imsi string) *Inventory {
	return &Inventory{Profiles: repo, ICCIDPrefix: iccidPrefix, IMSI: imsi}
}

// Allocate reserves a profile and creates a profile row. When req.ICCID is
// non-empty the reservation SHALL use exactly that value (SGP.22 §5.3.1 and
// Table 23: "If the ICCID was provided as input data, the reservation SHALL use
// this value"); otherwise a unique ICCID is taken from the tenant's pool or
// generated from the configured prefix. When req.EID is non-empty the profile
// starts in Linked, otherwise in Allocated (SGP.22 §3.1.6).
func (inv *Inventory) Allocate(req AllocateRequest) (*store.Profile, error) {
	state := store.StateAllocated
	if req.EID != "" {
		state = store.StateLinked
	}
	newProfile := func(iccid string) *store.Profile {
		return &store.Profile{
			ICCID:       iccid,
			EID:         req.EID,
			ProfileType: req.ProfileType,
			State:       state,
			IMSI:        inv.IMSI,
			UPPTemplate: req.UPPTemplate,
			TenantID:    req.Tenant,
			ExternalRef: req.ExternalRef,
		}
	}

	if req.ICCID != "" {
		iccid, err := canonicalICCID(req.ICCID)
		if err != nil {
			return nil, err
		}
		// Table 24 NOTE (SGP.22 §5.3.1): when the Profile is already in
		// Allocated/Linked state and this call would produce the same result,
		// the SM-DP+ MAY answer Executed-Success and do nothing. This is the
		// standard "graceful resend" path: it makes an operator retry after a
		// lost response safe without consuming a second ICCID.
		if existing, gerr := inv.Profiles.GetByICCID(iccid); gerr == nil {
			if sameResend(existing, req) {
				return existing, nil
			}
			return nil, fmt.Errorf("service: ICCID %s is already in use (state %s)", iccid, existing.State)
		} else if !errors.Is(gerr, store.ErrNotFound) {
			return nil, gerr
		}
		if err := inv.checkQuota(req.Tenant); err != nil {
			return nil, err
		}
		// An operator-supplied ICCID that the pool knows about must still obey
		// the pool: a blocked ICCID is never issued.
		if inv.Pool != nil {
			if state, serr := inv.Pool.State(iccid); serr == nil && state == "blocked" {
				return nil, fmt.Errorf("service: ICCID %s is blocked", iccid)
			} else if serr != nil && !errors.Is(serr, store.ErrNotFound) {
				return nil, serr
			}
		}
		p := newProfile(iccid)
		if _, err := inv.Profiles.Create(p); err != nil {
			return nil, fmt.Errorf("service: ICCID %s is not available: %w", iccid, err)
		}
		inv.claim(iccid, p.ID)
		return p, nil
	}

	if err := inv.checkQuota(req.Tenant); err != nil {
		return nil, err
	}

	// Prefer an operator-imported ICCID from the tenant's pool when one is
	// available. A failed profile insert returns the reservation to the pool.
	if inv.Pool != nil {
		if iccid, err := inv.Pool.Reserve(req.Tenant, req.EID, req.Reference, inv.ReserveTTL); err == nil {
			p := newProfile(iccid)
			if _, err := inv.Profiles.Create(p); err == nil {
				inv.claim(iccid, p.ID)
				return p, nil
			} else {
				_ = inv.Pool.SetState(iccid, "available", "")
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	for attempt := 0; attempt < 8; attempt++ {
		iccid, err := inv.generateICCID()
		if err != nil {
			return nil, err
		}
		p := newProfile(iccid)
		if _, err := inv.Profiles.Create(p); err != nil {
			continue // ICCID collision; retry
		}
		return p, nil
	}
	return nil, fmt.Errorf("service: could not allocate a unique ICCID")
}

// claim clears a pool reservation deadline once the ICCID is attached to a
// profile. Missing pool entries are ignored (generated ICCIDs are not pooled).
func (inv *Inventory) claim(iccid string, profileID int64) {
	if inv.Pool == nil {
		return
	}
	_ = inv.Pool.Claim(iccid, profileID)
}

// canonicalICCID normalizes and validates an operator-supplied ICCID: a single
// trailing 'F' padding nibble is removed; what remains must be 19 or 20 decimal
// digits with a valid Luhn check digit.
func canonicalICCID(s string) (string, error) {
	s = strings.TrimRight(s, "fF")
	if len(s) != 19 && len(s) != 20 {
		return "", fmt.Errorf("service: ICCID %q must be 19 or 20 digits", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", fmt.Errorf("service: ICCID %q contains a non-digit", s)
		}
	}
	if !rsp.LuhnValid(s) {
		return "", fmt.Errorf("service: ICCID %q has an invalid check digit", s)
	}
	return s, nil
}

// generateICCID builds a 19-digit ICCID: the configured prefix followed by
// random digits up to an 18-digit body, plus a Luhn check digit.
func (inv *Inventory) generateICCID() (string, error) {
	prefix := inv.ICCIDPrefix
	if prefix == "" {
		prefix = "8900012"
	}
	const bodyLen = 18 // 18-digit body + 1 check digit = 19 digits
	if len(prefix) > bodyLen {
		prefix = prefix[:bodyLen]
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	body := prefix
	for i := 0; len(body) < bodyLen; i++ {
		body += fmt.Sprintf("%d", int(rnd[i%len(rnd)])%10)
	}
	check, err := rsp.LuhnCheckDigit(body)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%c", body, '0'+check), nil
}
