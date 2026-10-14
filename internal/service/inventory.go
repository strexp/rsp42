package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// ICCIDPool reserves ICCIDs from an operator-managed pool.
type ICCIDPool interface {
	Reserve(eid string) (string, error)
}

// Inventory allocates ICCIDs and creates profile rows for ES2+.DownloadOrder. If
// a Pool is set it is preferred; otherwise an ICCID is generated on demand.
type Inventory struct {
	Profiles    ProfileCreator
	ICCIDPrefix string
	IMSI        string
	Pool        ICCIDPool
}

// NewInventory builds an Inventory.
func NewInventory(repo ProfileCreator, iccidPrefix, imsi string) *Inventory {
	return &Inventory{Profiles: repo, ICCIDPrefix: iccidPrefix, IMSI: imsi}
}

// Allocate reserves a profile and creates a profile row. When requestedICCID is
// non-empty the reservation SHALL use exactly that value (SGP.22 §5.3.1 and
// Table 23: "If the ICCID was provided as input data, the reservation SHALL use
// this value"); otherwise a unique ICCID is generated from the configured pool
// prefix. When eid is non-empty the profile starts in Linked, otherwise in
// Allocated (SGP.22 §3.1.6).
func (inv *Inventory) Allocate(eid, profileType, requestedICCID string) (*store.Profile, error) {
	state := store.StateAllocated
	if eid != "" {
		state = store.StateLinked
	}

	if requestedICCID != "" {
		iccid, err := canonicalICCID(requestedICCID)
		if err != nil {
			return nil, err
		}
		p := &store.Profile{
			ICCID:       iccid,
			EID:         eid,
			ProfileType: profileType,
			State:       state,
			IMSI:        inv.IMSI,
		}
		if _, err := inv.Profiles.Create(p); err != nil {
			return nil, fmt.Errorf("service: ICCID %s is not available: %w", iccid, err)
		}
		return p, nil
	}

	// Prefer an operator-imported ICCID from the pool when one is available.
	if inv.Pool != nil {
		if iccid, err := inv.Pool.Reserve(eid); err == nil {
			p := &store.Profile{ICCID: iccid, EID: eid, ProfileType: profileType, State: state, IMSI: inv.IMSI}
			if _, err := inv.Profiles.Create(p); err == nil {
				return p, nil
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
		p := &store.Profile{
			ICCID:       iccid,
			EID:         eid,
			ProfileType: profileType,
			State:       state,
			IMSI:        inv.IMSI,
		}
		if _, err := inv.Profiles.Create(p); err != nil {
			continue // ICCID collision; retry
		}
		return p, nil
	}
	return nil, fmt.Errorf("service: could not allocate a unique ICCID")
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
