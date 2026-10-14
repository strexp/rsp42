package service

import (
	"context"
	"errors"

	"rsp42/internal/activationcode"
	"rsp42/internal/iccid"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// handleACR implements the Activation Code Retrieval branch (SGP.22
// §3.1.7/§3.1.8). The eUICC's matchingId is ACR-<0|1>-<ICCID>.
func (c *CMAE) handleACR(ctx context.Context, transactionID string, ca *clientAuth) (*AuthenticateResult, error) {
	acr, err := activationcode.ParseACR(ca.MatchingID)
	if err != nil {
		return nil, rsp.CodeInputRefused.Status(err.Error())
	}
	profile, err := c.Profiles.GetByICCID(iccid.Normalize(acr.ICCID))
	if err != nil {
		return nil, rsp.CodeInputRefused.Status("unknown ICCID")
	}
	if profile.EID != "" && profile.EID != ca.EID {
		return nil, rsp.CodeInputRefused.Status("EID mismatch")
	}
	if profile.State != store.StateInstalled {
		return nil, rsp.CodeInputRefused.Status("profile is not installed")
	}

	// Confirm with the Operator when ES2+.HandleAcrRequest is configured
	// (SGP.22 §3.1.7 / §5.3.8). The Operator is asked for both ACR types —
	// redownload and availability check — before anything is issued.
	if c.ACRCheck != nil {
		if err := c.ACRCheck(ctx, profile); err != nil {
			c.notify(ctx, progressFor(profile, ca.EID, 17, "Failed"))
			if errors.Is(err, rsp.ErrACRRefused) {
				return nil, rsp.CodeACRNotAllowed.Status("Operator refused Activation Code Retrieval")
			}
			return nil, rsp.CodeInputRefused.Status("Activation Code Retrieval confirmation failed")
		}
	}

	var ssd []byte
	if acr.Check == 0 {
		token := "ACR-" + randomToken()
		profile.MatchingID = token
		if err := c.Profiles.Update(profile); err != nil {
			return nil, err
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
	if err := c.Sessions.Put(sess); err != nil {
		return nil, err
	}
	c.notify(ctx, progressFor(profile, ca.EID, 17, "Executed-Success"))
	return &AuthenticateResult{TransactionID: transactionID, ProfileMetadata: meta, ACROnly: true}, nil
}
