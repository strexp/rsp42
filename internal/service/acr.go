package service

import (
	"context"

	"rsp42/internal/activationcode"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// handleACR implements the Activation Code Retrieval branch (SGP.22
// §3.1.7/§3.1.8). The eUICC's matchingId is ACR-<0|1>-<ICCID>.
func (c *CMAE) handleACR(transactionID string, ca *clientAuth) (*AuthenticateResult, error) {
	acr, err := activationcode.ParseACR(ca.MatchingID)
	if err != nil {
		return nil, rsp.CodeInputRefused.Status(err.Error())
	}
	profile, err := c.Profiles.GetByICCID(normalizeICCID(acr.ICCID))
	if err != nil {
		return nil, rsp.CodeInputRefused.Status("unknown ICCID")
	}
	if profile.EID != "" && profile.EID != ca.EID {
		return nil, rsp.CodeInputRefused.Status("EID mismatch")
	}
	if profile.State != store.StateInstalled {
		return nil, rsp.CodeInputRefused.Status("profile is not installed")
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
	c.notify(context.Background(), ca.EID, profile.ICCID, 17, "Executed-Success")
	return &AuthenticateResult{TransactionID: transactionID, ProfileMetadata: meta, ACROnly: true}, nil
}
