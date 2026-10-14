package service

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"rsp42/internal/crypto"
	"rsp42/internal/rsp"
	"rsp42/internal/saip"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
)

// GetBoundProfilePackageResult is the ES9+.GetBoundProfilePackage response.
type GetBoundProfilePackageResult struct {
	TransactionID       string
	BoundProfilePackage []byte
}

// GetBoundProfilePackage implements ES9+.GetBoundProfilePackage (SGP.22 §5.6.2).
func (c *CMAE) GetBoundProfilePackage(transactionID string, prepareDownloadResponse []byte) (*GetBoundProfilePackageResult, error) {
	sess, err := c.Sessions.Get(transactionID)
	if err != nil {
		return nil, rsp.CodeUnknownTransaction.Status("Unknown TransactionID")
	}
	ok, errResp, err := rsp.DecodePrepareDownloadResponse(prepareDownloadResponse)
	if err != nil {
		return nil, rsp.CodeVerificationFailed.Status(err.Error())
	}
	if ok == nil {
		code := int64(127)
		if errResp != nil {
			code = errResp.DownloadErrorCode
		}
		return nil, rsp.CodeVerificationFailed.Status(fmt.Sprintf("downloadResponseError %d", code))
	}

	euiccSigned2Raw, err := rsp.ExtractEuiccSigned2(prepareDownloadResponse)
	if err != nil {
		return nil, rsp.CodeVerificationFailed.Status(err.Error())
	}
	euiccCert, err := x509.ParseCertificate(sess.EuiccCert)
	if err != nil {
		return nil, rsp.CodeVerificationFailed.Status("missing eUICC certificate")
	}
	pub, okPub := euiccCert.PublicKey.(*ecdsa.PublicKey)
	toVerify := append(append([]byte{}, euiccSigned2Raw...), sess.SmdpSignature2...)
	if !okPub || !crypto.VerifyRaw(pub, toVerify, rsp.SignatureValue(ok.EuiccSignature2)) {
		return nil, rsp.CodeVerificationFailed.Status("eUICC signature verification failed")
	}

	profile, err := c.Profiles.GetByID(sess.ProfileID)
	if err != nil {
		return nil, rsp.CodeUnknownTransaction.Status("Unknown profile")
	}

	if profile.CCRequired {
		expected := confirmationHash(profile.CCHash, mustHexLower(transactionID))
		if !equalBytes(expected, ok.EuiccSigned2.HashCc) {
			c.recordConfirmationFailure(profile)
			c.notify(context.Background(), sess.EID, profile.ICCID, 2, "Failed")
			return nil, rsp.CodeConfirmationCode.Status("Confirmation code invalid")
		}
	}

	upp, err := c.loadUPP(profile, sess)
	if err != nil {
		return nil, rsp.CodeProfileLoadFailed.Status(err.Error())
	}

	otSK := make([]byte, 32)
	if _, err := rand.Read(otSK); err != nil {
		return nil, err
	}
	otPK, err := crypto.ECPointFromPrivate(otSK)
	if err != nil {
		return nil, err
	}

	_, pbSigner := c.pbFor(sess)
	bpp, err := c.buildBPP(sess.EID, mustHexLower(transactionID), otPK, otSK, ok.EuiccSigned2.EuiccOtpk, upp, profile, pbSigner)
	if err != nil {
		return nil, err
	}

	// The Profile moves to Downloaded once the BPP has been produced
	// (SGP.22 §3.1.6 Table 6b); a re-download keeps it Downloaded. This is what
	// lets a subsequent install notification transition it to Installed.
	profile.State = store.StateDownloaded
	profile.ErrorReason = ""
	if err := c.Profiles.Update(profile); err != nil {
		return nil, err
	}

	sess.State = "downloaded"
	_ = c.Sessions.Put(sess)
	c.notify(context.Background(), sess.EID, profile.ICCID, 3, "Executed-Success")

	return &GetBoundProfilePackageResult{TransactionID: transactionID, BoundProfilePackage: bpp}, nil
}

// recordConfirmationFailure increments the per-Profile Confirmation Code attempt
// counter and, once the configured maximum is reached, moves the Profile to
// Error (SGP.22 §3.1.3 step 7).
func (c *CMAE) recordConfirmationFailure(p *store.Profile) {
	p.CCAttempts++
	if c.Cfg.MaxCCAttempts > 0 && p.CCAttempts >= c.Cfg.MaxCCAttempts {
		p.State = store.StateError
		p.ErrorReason = "confirmation code attempts exceeded"
	}
	_ = c.Profiles.Update(p)
}

func (c *CMAE) buildBPP(eid string, transactionID, smdpOtpk, smdpOtSK, euiccOtpk, upp []byte, profile *store.Profile, pbSigner stdcrypto.Signer) ([]byte, error) {
	eidBytes, err := rsp.EIDBytes(eid)
	if err != nil {
		return nil, err
	}
	shared, err := crypto.ECDHSharedSecret(smdpOtSK, euiccOtpk)
	if err != nil {
		return nil, err
	}

	iscr := &rsp.InitialiseSecureChannelRequest{
		RemoteOpID:    1,
		TransactionID: transactionID,
		ControlRefTemplate: rsp.ControlRefTemplate{
			KeyType: []byte{0x88}, KeyLen: []byte{0x10}, HostID: c.Cfg.HostID,
		},
		SmdpOtpk: smdpOtpk,
	}
	dpPbKey, err := ecdsaKey(pbSigner)
	if err != nil {
		return nil, err
	}
	sign, err := crypto.SignRaw(dpPbKey, iscr.SignedBytes(euiccOtpk))
	if err != nil {
		return nil, err
	}
	iscr.SmdpSign = sign

	configureISDP := (&rsp.ConfigureISDPRequest{DpOID: c.Cfg.OID}).Encode()
	storeMeta, err := c.buildStoreMetadata(profile)
	if err != nil {
		return nil, err
	}
	ppk, err := crypto.RandomKeyMaterial()
	if err != nil {
		return nil, err
	}
	rsr := &rsp.ReplaceSessionKeysRequest{
		InitialMacChainingValue: ppk.InitialMCV,
		PPKEnc:                  ppk.SEnc,
		PPKCmac:                 ppk.SMac,
	}
	bf26 := rsr.Encode()

	res, err := crypto.ProtectBPP(shared, c.Cfg.HostID, eidBytes, configureISDP, storeMeta, bf26, upp, &ppk)
	if err != nil {
		return nil, err
	}
	bpp := &rsp.BoundProfilePackage{
		InitialiseSecureChannelRequest: iscr,
		FirstSequenceOf87:              res.FirstSequenceOf87,
		SequenceOf88:                   res.SequenceOf88,
		SecondSequenceOf87:             res.SecondSequenceOf87,
		SequenceOf86:                   res.SequenceOf86,
	}
	return bpp.Assemble(), nil
}

// buildStoreMetadata builds the BF25 StoreMetadataRequest for a profile.
func (c *CMAE) buildStoreMetadata(profile *store.Profile) ([]byte, error) {
	return c.buildStoreMetadataWithSSD(profile, nil)
}

func (c *CMAE) buildStoreMetadataWithSSD(profile *store.Profile, ssd []byte) ([]byte, error) {
	iccidEF, err := personalization.ICCIDEFBytes(profile.ICCID)
	if err != nil {
		return nil, err
	}
	class := int64(2) // operational
	ppr := profile.PPRIds
	if len(ppr) == 0 {
		ppr = c.Cfg.PPRIds
	}
	req := &rsp.StoreMetadataRequest{
		ICCID:               iccidEF,
		ServiceProviderName: "RSP42",
		ProfileName:         profile.ProfileName(),
		ProfileClass:        &class,
		PPRIds:              ppr,
		ServiceSpecificData: ssd,
	}
	if len(ssd) == 0 {
		req.Notifications = []rsp.NotificationConfigurationInformation{
			{Operation: 0x40, Address: c.Cfg.FQDN}, // enable
			{Operation: 0x20, Address: c.Cfg.FQDN}, // disable
			{Operation: 0x10, Address: c.Cfg.FQDN}, // delete
		}
	}
	return req.Encode(), nil
}

// pickUPP returns the best UPP template for the eUICC's advertised profile
// version: the greatest major.minor not exceeding it. It returns "" when the
// version is unknown or no template qualifies.
func (c *CMAE) pickUPP(supported []byte) string {
	if len(supported) < 2 {
		return ""
	}
	major, minor := int(supported[0]), int(supported[1])
	entries, err := os.ReadDir(c.UPPDir)
	if err != nil {
		return ""
	}
	best := ""
	bestMaj, bestMin := -1, -1
	for _, e := range entries {
		fname := e.Name()
		if e.IsDir() || !strings.HasSuffix(fname, ".der") || strings.Contains(fname, "UNIQUE") {
			continue
		}
		mj, mn, ok := uppVersion(filepath.Join(c.UPPDir, fname))
		if !ok {
			continue
		}
		if mj > major || (mj == major && mn > minor) {
			continue // eUICC does not support this SAIP version
		}
		if mj > bestMaj || (mj == bestMaj && mn > bestMin) {
			best, bestMaj, bestMin = fname, mj, mn
		}
	}
	return best
}

// uppVersion reads the SAIP version from a UPP template's ProfileHeader.
func uppVersion(path string) (int, int, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	seq, err := saip.ParseUPP(raw)
	if err != nil {
		return 0, 0, false
	}
	h, err := saip.ParseHeader(seq.Header())
	if err != nil {
		return 0, 0, false
	}
	return int(h.Major), int(h.Minor), true
}

// loadUPP loads, personalizes and encodes the UPP template for a profile. The
// operator may pin a template on the order; otherwise the template selected for
// the session (from the eUICC's profile version) is used.
func (c *CMAE) loadUPP(profile *store.Profile, sess *store.Session) ([]byte, error) {
	name := profile.UPPTemplate
	if name == "" && sess != nil {
		name = sess.UPPTemplate
	}
	if name == "" {
		name = c.DefaultUPP
	}
	if name == "" {
		entries, err := os.ReadDir(c.UPPDir)
		if err != nil {
			return nil, fmt.Errorf("read upp dir: %w", err)
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".der") && !strings.Contains(e.Name(), "UNIQUE") {
				name = e.Name()
				break
			}
		}
	}
	if name == "" {
		return nil, fmt.Errorf("no UPP template available")
	}
	raw, err := os.ReadFile(filepath.Join(c.UPPDir, name))
	if err != nil {
		return nil, err
	}
	seq, err := saip.ParseUPP(raw)
	if err != nil {
		return nil, err
	}
	if c.Source != nil {
		data, err := c.Source.Next()
		if err != nil {
			return nil, err
		}
		if data != nil {
			// The download order owns the ICCID: it is what StoreMetadata
			// carries, so the personalized profile must use the same value even
			// if the personalization source supplies a different one.
			data.ICCID = profile.ICCID
			eng := c.Engine
			if eng == nil {
				eng = &personalization.Engine{}
			}
			if err := eng.Apply(seq, data); err != nil {
				return nil, err
			}
		}
	}
	return seq.Encode(), nil
}
