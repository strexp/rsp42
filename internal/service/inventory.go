package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"rsp42/internal/iccid"
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

// reusable reports whether an existing Profile row can be re-allocated by this
// request. SGP.22 Table 29 puts a cancelled order's Profile back into Available
// "available for future use", and the state machine allows
// Available --> Allocated/Linked on a new DownloadOrder, so the row is re-used
// in place: the Profile keeps its ICCID (and therefore its personalization).
//
// A Profile that was ever downloaded is deliberately NOT reused. The sanctioned
// redownload path is Installed -> Released after a Delete Notification, not a
// fresh DownloadOrder; reusing a downloaded row would hand the same credentials
// (ICCID/IMSI/Ki) to a second eUICC.
func reusable(p *store.Profile, req AllocateRequest) bool {
	return p.State == store.StateAvailable &&
		p.TenantID == req.Tenant &&
		p.DownloadAttempts == 0 &&
		p.InstalledAt == nil
}

// reallocate overwrites the download-order attributes of a reusable Profile.
// The identity (ICCID, IMSI) is preserved; every attribute that belonged to the
// cancelled order is cleared, so a stale MatchingID, confirmation code or SM-DS
// address cannot leak into the new order.
func reallocate(p *store.Profile, req AllocateRequest, state store.ProfileState) {
	p.State = state
	p.EID = req.EID
	p.ProfileType = req.ProfileType
	p.ExternalRef = req.ExternalRef
	p.UPPTemplate = req.UPPTemplate
	p.MatchingID = ""
	p.CCHash = nil
	p.CCRequired = false
	p.SMDSAddress = ""
	p.ReleaseFlag = false
	p.ErrorReason = ""
}

// ICCIDPool reserves and recycles ICCIDs from an operator-managed pool.
type ICCIDPool interface {
	Reserve(tenant, eid, reference string, ttl time.Duration) (string, error)
	Claim(iccid string, profileID int64) error
	SetState(iccid, state, note string) error
	// Get reports a pool entry (state, owning tenant), or store.ErrNotFound when
	// the ICCID is not managed by the pool at all.
	Get(iccid string) (*store.ICCIDPoolEntry, error)
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

// ErrInvalidICCID reports an operator-supplied ICCID that is not syntactically
// valid (19 or 20 digits with a valid Luhn check digit). It is separate from
// ErrICCIDInUse so the interfaces can answer "invalid request" instead of a
// conflict (the ES2+ and admin layers have different codes for the two).
var ErrInvalidICCID = errors.New("service: invalid iccid")

// ErrICCIDInUse indicates that an operator-supplied ICCID cannot be issued
// (already in use, blocked, or owned by another tenant). It lets the ES2+ layer
// answer 8.2.1/3.3 instead of a generic allocation failure (C3).
var ErrICCIDInUse = errors.New("service: iccid not available")

// ErrNoProfileAvailable indicates that the requested Profile Type has no usable
// ICCID: the pool has no entry left, or the entry it offered cannot be issued
// (its Profile row is not reusable). It maps to the same ES2+ code as quota
// exhaustion (8.2.5/3.7): "no Profile available for the requested Profile Type".
var ErrNoProfileAvailable = errors.New("service: no profile available")

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

// checkPool applies the pool's rules to an ICCID this caller named explicitly.
// A blocked entry is never issued, and an entry owned by another tenant is not
// this caller's to take (tenant isolation). An ICCID the pool does not know
// about is allowed: the pool is an optional inventory source, not a closed
// world, so a deployment that never imports ranges keeps working.
func (inv *Inventory) checkPool(iccid, tenant string) error {
	if inv.Pool == nil {
		return nil
	}
	e, err := inv.Pool.Get(iccid)
	switch {
	case err == nil:
		if e.State == "blocked" {
			return fmt.Errorf("%w: ICCID %s is blocked", ErrICCIDInUse, iccid)
		}
		if e.TenantID != tenant {
			return fmt.Errorf("%w: ICCID %s belongs to another tenant", ErrICCIDInUse, iccid)
		}
		return nil
	case errors.Is(err, store.ErrNotFound):
		return nil
	default:
		return err
	}
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
//
// An ICCID whose Profile is already in Allocated/Linked is a resend (Table 24
// NOTE) and an ICCID whose Profile is back in Available is re-allocated in place
// (Table 29); every other state is 8.2.1/3.3 / a conflict.
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
			return nil, fmt.Errorf("%w: %w", ErrInvalidICCID, err)
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
			// A cancelled order leaves the row in Available. Table 29 says the
			// ICCID is then "available for future use", so re-issue the same
			// Profile row instead of refusing it (Q1). The quota is not
			// re-checked: the row already counts against it.
			if !reusable(existing, req) {
				return nil, fmt.Errorf("%w: ICCID %s is already in use (state %s)", ErrICCIDInUse, iccid, existing.State)
			}
			if err := inv.checkPool(iccid, req.Tenant); err != nil {
				return nil, err
			}
			if err := inv.claimReused(existing); err != nil {
				return nil, err
			}
			reallocate(existing, req, state)
			if err := inv.Profiles.Update(existing); err != nil {
				return nil, err
			}
			return existing, nil
		} else if !errors.Is(gerr, store.ErrNotFound) {
			return nil, gerr
		}
		if err := inv.checkQuota(req.Tenant); err != nil {
			return nil, err
		}
		if err := inv.checkPool(iccid, req.Tenant); err != nil {
			return nil, err
		}
		p := newProfile(iccid)
		if _, err := inv.Profiles.Create(p); err != nil {
			return nil, fmt.Errorf("%w: ICCID %s is not available: %w", ErrICCIDInUse, iccid, err)
		}
		if err := inv.claimReservation(p); err != nil {
			return nil, err
		}
		return p, nil
	}

	if err := inv.checkQuota(req.Tenant); err != nil {
		return nil, err
	}

	// Prefer an operator-imported ICCID from the tenant's pool when one is
	// available. A generation from the configured prefix is the fallback for a
	// tenant whose pool is empty, not for one whose pool entry cannot be issued:
	// minting an ICCID outside the operator's inventory would leak a value the
	// operator never imported.
	if inv.Pool != nil {
		iccid, err := inv.Pool.Reserve(req.Tenant, req.EID, req.Reference, inv.ReserveTTL)
		switch {
		case err == nil:
			p := newProfile(iccid)
			_, cerr := inv.Profiles.Create(p)
			if cerr == nil {
				if err := inv.claimReservation(p); err != nil {
					return nil, err
				}
				return p, nil
			}
			if store.IsUniqueViolation(cerr) {
				// The pool offered an ICCID that already has a Profile row. After
				// a cancelOrder{Available} that row is re-issuable (Q1); in any
				// other state it is not.
				existing, gerr := inv.Profiles.GetByICCID(iccid)
				switch {
				case gerr == nil && reusable(existing, req):
					if err := inv.claimReused(existing); err != nil {
						return nil, err
					}
					reallocate(existing, req, state)
					if err := inv.Profiles.Update(existing); err != nil {
						return nil, err
					}
					return existing, nil
				case gerr != nil && !errors.Is(gerr, store.ErrNotFound):
					return nil, gerr
				}
				// Not reusable (another tenant, or already downloaded). Hand the
				// reservation back and fail: the caller must fix the pool entry
				// rather than be served an ICCID from outside the pool.
				if rerr := inv.Pool.SetState(iccid, "available", ""); rerr != nil {
					return nil, fmt.Errorf("service: release reservation %s: %w", iccid, rerr)
				}
				return nil, fmt.Errorf("%w: pooled ICCID %s already has a Profile", ErrNoProfileAvailable, iccid)
			}
			// A storage failure: the reservation is useless, so hand it back. A
			// failed release is surfaced because the ICCID would otherwise leak.
			if rerr := inv.Pool.SetState(iccid, "available", ""); rerr != nil {
				return nil, fmt.Errorf("service: release reservation %s: %w", iccid, rerr)
			}
			return nil, fmt.Errorf("service: create profile %s: %w", iccid, cerr)
		case errors.Is(err, store.ErrNotFound):
			// No pooled ICCID for this tenant: fall through to generation.
		default:
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
			if store.IsUniqueViolation(err) {
				continue // ICCID collision: try the next candidate
			}
			return nil, fmt.Errorf("service: create profile %s: %w", iccid, err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("service: could not allocate a unique ICCID")
}

// claimReservation attaches a freshly created profile to its pool entry. When
// the claim fails the profile row is removed again: the reservation would
// otherwise lapse and ReleaseExpired could hand the same ICCID out a second
// time while a profile still referenced it.
func (inv *Inventory) claimReservation(p *store.Profile) error {
	if inv.Pool == nil {
		return nil
	}
	if err := inv.Pool.Claim(p.ICCID, p.ID); err != nil {
		_ = inv.Profiles.Delete(p.ICCID)
		return fmt.Errorf("service: claim ICCID %s: %w", p.ICCID, err)
	}
	return nil
}

// claimReused attaches a re-issued (pre-existing) Profile to its pool entry.
// Unlike claimReservation it never deletes the row on failure: the row predates
// this call, and "Available row, unclaimed pool entry" is a consistent state the
// next attempt can re-issue from.
func (inv *Inventory) claimReused(p *store.Profile) error {
	if inv.Pool == nil {
		return nil
	}
	if err := inv.Pool.Claim(p.ICCID, p.ID); err != nil {
		return fmt.Errorf("service: claim ICCID %s: %w", p.ICCID, err)
	}
	return nil
}

// canonicalICCID normalizes and validates an operator-supplied ICCID. The rules
// (trailing 'F' padding, 19/20 digits, Luhn check digit) live in internal/iccid
// so the services and the persistence layer agree on them.
func canonicalICCID(s string) (string, error) {
	return iccid.Canonical(s)
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
	check, err := iccid.LuhnCheckDigit(body)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%c", body, '0'+check), nil
}
