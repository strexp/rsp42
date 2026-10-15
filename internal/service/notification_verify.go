package service

import (
	"crypto/ecdsa"
	"crypto/x509"

	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

func verifyPIRSignature(euiccCertDER []byte, pir *rsp.ProfileInstallationResult) bool {
	if len(euiccCertDER) == 0 || len(pir.DataRaw) == 0 || len(pir.EuiccSign) == 0 {
		return false
	}
	c, err := x509.ParseCertificate(euiccCertDER)
	if err != nil {
		return false
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return crypto.VerifyRaw(pub, pir.DataRaw, rsp.SignatureValue(pir.EuiccSign))
}

func (n *NotificationService) handleOtherSigned(o *rsp.OtherSignedNotification) error {
	if o == nil || o.Notification == nil {
		return nil
	}
	iccid := ""
	var profile *store.Profile
	if len(o.Notification.ICCID) > 0 {
		iccid = iccidDecimal(o.Notification.ICCID)
		if iccid != "" && n.Deps.Profiles != nil {
			profile, _ = n.Deps.Profiles.GetByICCID(iccid)
		}
	}

	// euiccNotificationSignature is signed over tbsOtherNotification
	// (NotificationMetadata, BF2F) with SK.EUICC.ECDSA (SGP.22 §5.7.9). The eUICC
	// and EUM certificates are carried in the notification itself.
	ok := n.verifyOtherSigned(o)
	if !ok && n.Deps.Log != nil {
		n.Deps.Log.Warn("euiccNotificationSignature verification failed; notification ignored")
	}
	// The usage of enable/disable/delete notifications is operator-defined
	// (SGP.22 §3.5); record them faithfully with their verification outcome.
	n.record(&store.Notification{
		EID:         eidOf(profile),
		SeqNumber:   o.Notification.SeqNumber,
		Operation:   operationName(o.Notification.Operation),
		ICCID:       iccid,
		SignatureOK: ok,
		Processed:   ok,
	})
	// A verified Delete Notification means the Profile is no longer on the
	// eUICC, which is the condition SGP.22 §3.1.7 attaches to letting its
	// Activation Code be used again ("the SM-DP+ is configured in such a way
	// that it will allow a Profile ... to be redownloaded after the reception
	// of the associated Delete Notification"). Only a verified signature and,
	// when configured, an existing Profile may trigger the state change.
	if ok && n.Deps.AllowRedownloadAfterDelete && profile != nil &&
		operationName(o.Notification.Operation) == "delete" &&
		profile.State == store.StateInstalled {
		if err := n.markRedownloadable(profile); err != nil && n.Deps.Log != nil {
			n.Deps.Log.Warn("redownload-after-delete transition",
				"iccid", profile.ICCID, "err", err)
		}
	}
	return nil
}

// markRedownloadable returns an installed Profile to Released so the Activation
// Code it currently carries can be used again (SGP.22 §3.1.7). It goes through
// the order state machine, which permits Installed -> Released.
func (n *NotificationService) markRedownloadable(profile *store.Profile) error {
	if n.Deps.Orders == nil {
		profile.State = store.StateReleased
		return n.Deps.Profiles.Update(profile)
	}
	if _, err := n.Deps.Orders.Release(profile.ICCID); err != nil {
		return err
	}
	if n.Deps.Log != nil {
		n.Deps.Log.Info("profile released for redownload after delete notification",
			"iccid", profile.ICCID)
	}
	return nil
}

// iccidDecimal decodes an Iccid as carried in a NotificationMetadata (EF.ICCID
// nibble-swapped BCD) to its decimal representation.

func (n *NotificationService) verifyOtherSigned(o *rsp.OtherSignedNotification) bool {
	if o == nil || o.Notification == nil || len(o.TbsRaw) == 0 ||
		len(o.EuiccSignature) == 0 || len(o.EuiccCertificate) == 0 {
		return false
	}
	euicc, err := x509.ParseCertificate(o.EuiccCertificate)
	if err != nil {
		return false
	}
	if n.Deps.Certs != nil && n.Deps.Certs.CI() != nil {
		if len(o.EumCertificate) == 0 {
			return false
		}
		eum, err := x509.ParseCertificate(o.EumCertificate)
		if err != nil {
			return false
		}
		ci := n.Deps.Certs.CIByAKI(eum.AuthorityKeyId)
		if ci == nil {
			ci = n.Deps.Certs.CI()
		}
		if err := cert.ValidateEUICCChain(euicc, eum, nil, ci, ci.SubjectKeyId); err != nil {
			return false
		}
	}
	pub, ok := euicc.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return crypto.VerifyRaw(pub, o.TbsRaw, rsp.SignatureValue(o.EuiccSignature))
}

// record persists a notification row when a store is configured.
