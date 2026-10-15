package service

import (
	"context"
	"errors"

	"rsp42/internal/activationcode"
	"rsp42/internal/iccid"
	"rsp42/internal/rsp"
	"rsp42/internal/rsp/status"
	"rsp42/internal/store"
)

// handleACR implements the Activation Code Retrieval branch (SGP.22
// §3.1.7/§3.1.8). The eUICC's matchingId is ACR-<0|1>-<ICCID>.
func (c *CMAE) handleACR(ctx context.Context, transactionID string, ca *clientAuth) (*AuthenticateResult, error) {
	acr, err := activationcode.ParseACR(ca.MatchingID)
	if err != nil {
		return nil, status.CodeInputRefused.Status(err.Error())
	}
	profile, err := c.Deps.Profiles.GetByICCID(iccid.Normalize(acr.ICCID))
	if err != nil {
		return nil, status.CodeInputRefused.Status("unknown ICCID")
	}
	if profile.EID != "" && profile.EID != ca.EID {
		return nil, status.CodeInputRefused.Status("EID mismatch")
	}
	if profile.State != store.StateInstalled {
		return nil, status.CodeInputRefused.Status("profile is not installed")
	}

	// Confirm with the Operator when ES2+.HandleAcrRequest is configured
	// (SGP.22 §3.1.7 / §5.3.8). The Operator is asked for both ACR types —
	// redownload and availability check — before anything is issued.
	if c.ACRCheck != nil {
		if err := c.ACRCheck(ctx, profile); err != nil {
			c.notify(ctx, progressFor(profile, ca.EID, 17, "Failed"))
			if errors.Is(err, rsp.ErrACRRefused) {
				return nil, status.CodeACRNotAllowed.Status("Operator refused Activation Code Retrieval")
			}
			return nil, status.CodeInputRefused.Status("Activation Code Retrieval confirmation failed")
		}
	}

	var ssd []byte
	if acr.Check == 0 {
		// The redownload Activation Code carries a fresh MatchingID. It must NOT
		// live in the ACR namespace ("ACR-<0|1>-<ICCID>", SGP.22 §4.9.1): an
		// "ACR-"-prefixed value would be routed back into this function by
		// activationcode.IsACR, so the Activation Code handed to the end user
		// could never be used. Use the same "MATCH-" shape confirmOrder
		// auto-generates.
		token := "MATCH-" + randomToken()
		previous := profile.MatchingID
		profile.MatchingID = token
		if err := c.Deps.Profiles.Update(profile); err != nil {
			return nil, err
		}
		// The SM-DS registration is keyed by the MatchingID (§3.6), so the one
		// held under the previous value is stale now. The new code is delivered
		// directly, so no new event is registered; the hook only cleans up.
		if previous != "" && previous != token && c.MatchingIDChanged != nil {
			c.MatchingIDChanged(profile, previous)
		}
		ac := &activationcode.Code{FQDN: c.Cfg.FQDN, MatchingID: token}
		ssd = rsp.ACRRedownload(ac.String())
	} else {
		ssd = rsp.ACRAvailable()
	}

	meta, err := c.buildStoreMetadataWithSSD(profile, ssd)
	if err != nil {
		return nil, err
	}
	sess := ca.Session
	sess.State = "acr"
	sess.EID = ca.EID
	sess.ProfileID = profile.ID
	if err := c.Deps.Sessions.Put(sess); err != nil {
		return nil, err
	}
	c.notify(ctx, progressFor(profile, ca.EID, 17, "Executed-Success"))
	return &AuthenticateResult{TransactionID: transactionID, ProfileMetadata: meta, ACROnly: true}, nil
}
