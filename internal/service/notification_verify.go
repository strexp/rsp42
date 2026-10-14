package service

import (
	"crypto/ecdsa"
	"crypto/x509"

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
		if iccid != "" && n.Profiles != nil {
			profile, _ = n.Profiles.GetByICCID(iccid)
		}
	}

	// euiccNotificationSignature is signed over tbsOtherNotification
	// (NotificationMetadata, BF2F) with SK.EUICC.ECDSA (SGP.22 §5.7.9). The eUICC
	// and EUM certificates are carried in the notification itself.
	ok := n.verifyOtherSigned(o)
	if !ok && n.Log != nil {
		n.Log.Warn("euiccNotificationSignature verification failed; notification ignored")
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
	if n.Certs != nil && n.Certs.CI() != nil {
		if len(o.EumCertificate) == 0 {
			return false
		}
		eum, err := x509.ParseCertificate(o.EumCertificate)
		if err != nil {
			return false
		}
		ci := n.Certs.CIByAKI(eum.AuthorityKeyId)
		if ci == nil {
			ci = n.Certs.CI()
		}
		if err := validateEUICCChain(euicc, eum, nil, ci, ci.SubjectKeyId); err != nil {
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
