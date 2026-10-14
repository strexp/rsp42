package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"log/slog"
	"strings"

	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// OperatorCallback delivers an ES2+.HandleDownloadProgressInfo notification to
// the operator. It is optional.
type OperatorCallback func(ctx context.Context, eid, iccid string, pointID int, statusJSON string) error

// NotificationService processes ES9+.HandleNotification payloads and drives
// operator callbacks (SGP.22 §3.5).
type NotificationService struct {
	Log       *slog.Logger
	Notifs    NotificationStore
	Profiles  ProfileStore
	Orders    *OrderService
	Sessions  *SessionService
	Certs     *cert.Manager
	Callback  OperatorCallback
	Registrar *Registrar
}

// NewNotificationService builds a NotificationService.
func NewNotificationService(log *slog.Logger, notifs NotificationStore, profiles ProfileStore, orders *OrderService) *NotificationService {
	return &NotificationService{Log: log, Notifs: notifs, Profiles: profiles, Orders: orders}
}

// HandlePendingNotification processes a PendingNotification (SGP.22 §5.6.4).
func (n *NotificationService) HandlePendingNotification(ctx context.Context, raw []byte) error {
	pn, err := rsp.DecodePendingNotification(raw)
	if err != nil {
		if n.Log != nil {
			n.Log.Warn("handleNotification decode", "err", err)
		}
		return err
	}
	if pn.InstallationResult != nil {
		return n.handleInstallation(ctx, pn.InstallationResult)
	}
	if pn.OtherSigned != nil {
		return n.handleOtherSigned(pn.OtherSigned)
	}
	return nil
}

func (n *NotificationService) handleInstallation(ctx context.Context, pir *rsp.ProfileInstallationResult) error {
	if pir.Data == nil {
		return nil
	}
	txn := strings.ToUpper(hex.EncodeToString(pir.Data.TransactionID))
	var profile *store.Profile
	sigOK := false
	if n.Sessions != nil {
		if sess, err := n.Sessions.Get(txn); err == nil {
			// euiccSignPIR is signed over ProfileInstallationResultData (BF27) with
			// SK.EUICC.ECDSA; verify it against the session eUICC certificate
			// (SGP.22 §2.5.6 / §2.6.7.2).
			sigOK = verifyPIRSignature(sess.EuiccCert, pir)
			if sess.ProfileID != 0 {
				profile, _ = n.Profiles.GetByID(sess.ProfileID)
			}
		}
	}

	iccid := ""
	if profile != nil {
		iccid = profile.ICCID
	}

	if !sigOK {
		// The installation result could not be authenticated. Record it but do
		// not act on it (no profile state change).
		if n.Log != nil {
			n.Log.Warn("euiccSignPIR verification failed; notification ignored", "txn", txn)
		}
		n.record(&store.Notification{
			EID: eidOf(profile), Operation: "install", ICCID: iccid,
			TransactionID: txn, SignatureOK: false, Processed: false,
		})
		return nil
	}

	fr := pir.Data.FinalResult
	if fr != nil && profile != nil {
		if fr.Success {
			if _, err := n.Orders.MarkInstalled(profile.ICCID); err != nil && n.Log != nil {
				n.Log.Warn("mark installed", "iccid", profile.ICCID, "err", err)
			}
			if n.Registrar != nil && profile.EID != "" {
				if err := n.Registrar.DeleteForEID(profile.EID); err != nil && n.Log != nil {
					n.Log.Warn("ES12 delete event on install", "eid", profile.EID, "err", err)
				}
			}
		} else {
			// Some reasons are transient; keep the profile Downloaded.
			switch fr.ErrorReason {
			case 11: // installFailedDueToInterruption
			default:
				if _, err := n.Orders.MarkError(profile.ICCID, "install failed"); err != nil && n.Log != nil {
					n.Log.Warn("mark error", "iccid", profile.ICCID, "err", err)
				}
			}
		}
	}

	n.record(&store.Notification{
		EID: eidOf(profile), Operation: "install", ICCID: iccid,
		TransactionID: txn, SignatureOK: true, Processed: true,
	})
	if n.Sessions != nil {
		_ = n.Sessions.Delete(txn)
	}
	n.notify(ctx, eidOf(profile), iccid, 4, "Executed-Success")
	return nil
}

// verifyPIRSignature checks euiccSignPIR over the ProfileInstallationResultData
// (BF27) using the eUICC certificate from the download session.
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
func iccidDecimal(b []byte) string {
	var sb strings.Builder
	for _, by := range b {
		sb.WriteByte(hexDigit(by & 0x0f))
		sb.WriteByte(hexDigit(by >> 4))
	}
	return strings.TrimRight(sb.String(), "Ff")
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}

// verifyOtherSigned validates the eUICC certificate chain carried in an
// OtherSignedNotification and its euiccNotificationSignature. When no cert
// provider is configured only the signature is checked.
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
func (n *NotificationService) record(notif *store.Notification) {
	if n.Notifs == nil {
		return
	}
	_ = n.Notifs.Insert(notif)
}

func (n *NotificationService) notify(ctx context.Context, eid, iccid string, pointID int, status string) {
	if n.Callback == nil {
		return
	}
	if err := n.Callback(ctx, eid, iccid, pointID, status); err != nil && n.Log != nil {
		n.Log.Warn("operator callback failed", "point", pointID, "err", err)
	}
}

func operationName(mask uint8) string {
	switch {
	case mask&0x80 != 0:
		return "install"
	case mask&0x40 != 0:
		return "enable"
	case mask&0x20 != 0:
		return "disable"
	case mask&0x10 != 0:
		return "delete"
	}
	return "unknown"
}

func eidOf(p *store.Profile) string {
	if p == nil {
		return ""
	}
	return p.EID
}
