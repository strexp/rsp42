package service

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	"rsp42/internal/crypto"
	"rsp42/internal/rsp"
	"rsp42/internal/saip"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/saipver"
	"rsp42/internal/store"
)

// GetBoundProfilePackageResult is the ES9+.GetBoundProfilePackage response.
type GetBoundProfilePackageResult struct {
	TransactionID       string
	BoundProfilePackage []byte
}

// GetBoundProfilePackage implements ES9+.GetBoundProfilePackage (SGP.22 §5.6.2).
func (c *CMAE) GetBoundProfilePackage(transactionID string, prepareDownloadResponse []byte) (*GetBoundProfilePackageResult, error) {
	sess, err := c.Deps.Sessions.Get(transactionID)
	if err != nil {
		return nil, rsp.CodeUnknownTransaction.Status("Unknown TransactionID")
	}
	// The session lookup already proved that the TransactionID is a valid
	// session key; decode it once, and treat a malformed value as an error
	// rather than a panic.
	txn, err := hexLower(transactionID)
	if err != nil {
		return nil, rsp.CodeVerificationFailed.Status(err.Error())
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

	profile, err := c.Deps.Profiles.GetByID(sess.ProfileID)
	if err != nil {
		return nil, rsp.CodeUnknownTransaction.Status("Unknown profile")
	}

	if profile.CCRequired {
		expected := confirmationHash(profile.CCHash, txn)
		if !bytes.Equal(expected, ok.EuiccSigned2.HashCc) {
			c.recordConfirmationFailure(profile)
			c.notify(context.Background(), progressFor(profile, sess.EID, 2, "Failed"))
			return nil, rsp.CodeConfirmationCode.Status("Confirmation code invalid")
		}
	}

	upp, err := c.loadUPP(profile, sess)
	if err != nil {
		var vErr *ErrProfileVersionNotSupported
		if errors.As(err, &vErr) {
			// N12: no BoundProfilePackage segment has been produced yet, so the
			// eUICC receives a clean, distinguishable failure instead of a
			// package it would reject at the end of the download.
			c.noteVersionFailure(profile.TenantID, profile, vErr)
			return nil, rsp.CodeProfileVersionNotSupported.Status(vErr.Error())
		}
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
	bpp, err := c.buildBPP(sess.EID, txn, otPK, otSK, ok.EuiccSigned2.EuiccOtpk, upp, profile, pbSigner)
	if err != nil {
		return nil, err
	}

	// The Profile moves to Downloaded once the BPP has been produced
	// (SGP.22 §3.1.6 Table 6b); a re-download keeps it Downloaded. This is what
	// lets a subsequent install notification transition it to Installed.
	profile.State = store.StateDownloaded
	profile.ErrorReason = ""
	if err := c.Deps.Profiles.Update(profile); err != nil {
		return nil, err
	}

	sess.State = "downloaded"
	_ = c.Deps.Sessions.Put(sess)
	c.notify(context.Background(), progressFor(profile, sess.EID, 3, "Executed-Success"))

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
	_ = c.Deps.Profiles.Update(p)
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

	configureISDP, err := (&rsp.ConfigureISDPRequest{DpOID: c.Cfg.OID}).Encode()
	if err != nil {
		return nil, fmt.Errorf("configureISDP: %w", err)
	}
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
	req := &rsp.StoreMetadataRequest{
		ICCID:               iccidEF,
		ServiceProviderName: "RSP42",
		ProfileName:         profile.ProfileName(),
		ProfileClass:        &class,
		PPRIds:              c.effectivePPRIDs(profile),
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

// ErrProfileVersionNotSupported reports that no UPP template compatible with
// the eUICC's advertised SAIP versions is available (N12). It must fail the
// download before any BoundProfilePackage segment is produced, so the eUICC
// never sees a template it would reject at the very end of the download.
type ErrProfileVersionNotSupported struct {
	// EuiccProfileVersion is the base SAIP version the eUICC declared, or ""
	// when the session carries no version information.
	EuiccProfileVersion string
	// SupportedVersions lists every version the eUICC declared.
	SupportedVersions []string
	// LowestTemplateVersion is the lowest template version that was considered,
	// or "" when no template could be loaded at all.
	LowestTemplateVersion string
}

func (e *ErrProfileVersionNotSupported) Error() string {
	if len(e.SupportedVersions) == 0 {
		return "eUICC advertised no usable SAIP profile version; no template can be selected"
	}
	if e.LowestTemplateVersion == "" {
		return fmt.Sprintf("no UPP template compatible with the eUICC's SAIP versions %v",
			e.SupportedVersions)
	}
	return fmt.Sprintf("no UPP template compatible with the eUICC's SAIP versions %v (lowest registered template is %s)",
		e.SupportedVersions, e.LowestTemplateVersion)
}

// sessionVersions decodes the SAIP version set persisted on a session at
// AuthenticateClient (N11).
func sessionVersions(sess *store.Session) []saipver.Version {
	if sess == nil {
		return nil
	}
	var out []saipver.Version
	for _, s := range sess.EuiccSupportedVersions {
		if v, err := saipver.Parse(s); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// resolveUPPTemplate returns the template loadUPP must use, enforcing N12's
// version compatibility at every fallback level. The resolution order is: the
// template pinned on the order, then the template selected for the session,
// then the best template the eUICC's version set supports, then the tenant
// default, then the global default.
//
// A pinned template (order or session) is authoritative: when it is missing or
// incompatible the download fails instead of silently substituting another
// template. Soft defaults (tenant/global) may fall through to each other. There
// is deliberately no "any template" fallback, and an unknown version set never
// selects a template.
func (c *CMAE) resolveUPPTemplate(profile *store.Profile, sess *store.Session) (*store.UPPTemplate, error) {
	if c.Deps.UPP == nil {
		return nil, fmt.Errorf("no UPP template registry configured")
	}
	tenant := profile.TenantID
	supported := sessionVersions(sess)

	type candidate struct {
		name     string
		explicit bool
		tpl      *store.UPPTemplate
	}
	var cands []candidate
	if profile.UPPTemplate != "" {
		cands = append(cands, candidate{name: profile.UPPTemplate, explicit: true})
	}
	if sess != nil && sess.UPPTemplate != "" {
		cands = append(cands, candidate{name: sess.UPPTemplate, explicit: true})
	}
	if len(supported) > 0 {
		if best, err := c.Deps.UPP.SelectBestFor(tenant, supported); err == nil && best != nil {
			cands = append(cands, candidate{name: best.Name, tpl: best})
		}
	}
	if c.Deps.Tenants != nil {
		def, err := c.Deps.Tenants.DefaultUPPForTenant(tenant)
		if err != nil {
			return nil, err
		}
		if def != "" {
			cands = append(cands, candidate{name: def})
		}
	}
	if c.Deps.DefaultUPP != "" {
		cands = append(cands, candidate{name: c.Deps.DefaultUPP})
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no UPP template configured for tenant %q", tenant)
	}

	rej := &ErrProfileVersionNotSupported{
		SupportedVersions: saipver.Strings(supported),
	}
	if sess != nil {
		rej.EuiccProfileVersion = sess.EuiccProfileVersion
	}
	var lowest *saipver.Version
	var missing error
	var loaded bool
	for _, cand := range cands {
		tpl := cand.tpl
		if tpl == nil {
			var err error
			tpl, err = c.Deps.UPP.GetForTenant(tenant, cand.name)
			if err != nil {
				if cand.explicit {
					return nil, fmt.Errorf("UPP template %q: %w", cand.name, err)
				}
				if missing == nil {
					missing = fmt.Errorf("UPP template %q: %w", cand.name, err)
				}
				continue
			}
		}
		loaded = true
		v := saipver.Version{Major: tpl.SAIPMajor, Minor: tpl.SAIPMinor}
		if lowest == nil || v.Compare(*lowest) < 0 {
			vv := v
			lowest = &vv
		}
		if !saipver.CompatibleWith(v, supported) {
			if cand.explicit {
				rej.LowestTemplateVersion = v.String()
				return nil, rej
			}
			continue
		}
		return tpl, nil
	}
	if !loaded && missing != nil {
		// Nothing in the registry could even be loaded: report the template
		// resolution failure rather than a version mismatch.
		return nil, missing
	}
	if lowest != nil {
		rej.LowestTemplateVersion = lowest.String()
	}
	return nil, rej
}

// loadUPP resolves, personalizes and encodes the UPP template for a profile.
func (c *CMAE) loadUPP(profile *store.Profile, sess *store.Session) ([]byte, error) {
	tpl, err := c.resolveUPPTemplate(profile, sess)
	if err != nil {
		return nil, err
	}
	seq, err := saip.ParseUPP(tpl.Bytes)
	if err != nil {
		return nil, err
	}

	// The download order owns the ICCID: it is what StoreMetadata carries, so
	// the personalized profile must always use the same value. Per-ICCID
	// personalization values are merged on top when present.
	data := &personalization.Data{ICCID: profile.ICCID, IMSI: profile.IMSI}
	if c.Deps.Personalization != nil {
		pd, err := c.Deps.Personalization.Resolve(profile.TenantID, profile.ICCID, profile.IMSI)
		if err != nil {
			return nil, err
		}
		if pd != nil {
			data = pd
			data.ICCID = profile.ICCID
		}
	}
	eng := c.Deps.Engine
	if eng == nil {
		eng = &personalization.Engine{}
	}
	if err := eng.Apply(seq, data); err != nil {
		return nil, err
	}
	return seq.Encode(), nil
}
