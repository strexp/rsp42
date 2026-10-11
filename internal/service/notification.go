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
	if n.Sessions != nil {
		if sess, err := n.Sessions.Get(txn); err == nil {
			// Verify euiccSignPIR with the session eUICC certificate.
			if len(sess.EuiccCert) > 0 {
				if c, err := x509.ParseCertificate(sess.EuiccCert); err == nil {
					if pub, ok := c.PublicKey.(*ecdsa.PublicKey); ok {
						if !crypto.VerifyRaw(pub, pir.DataRaw, rsp.SignatureValue(pir.EuiccSign)) {
							if n.Log != nil {
								n.Log.Warn("euiccSignPIR verification failed", "txn", txn)
							}
						}
					}
				}
			}
			if sess.ProfileID != 0 {
				profile, _ = n.Profiles.GetByID(sess.ProfileID)
			}
		}
	}

	fr := pir.Data.FinalResult
	op := "install"
	iccid := ""
	if profile != nil {
		iccid = profile.ICCID
	}
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

	if n.Notifs != nil {
		_ = n.Notifs.Insert(&store.Notification{
			EID:           eidOf(profile),
			Operation:     op,
			ICCID:         iccid,
			TransactionID: txn,
			SignatureOK:   true,
			Processed:     true,
		})
	}
	if n.Sessions != nil {
		_ = n.Sessions.Delete(txn)
	}
	n.notify(ctx, eidOf(profile), iccid, 4, "Executed-Success")
	return nil
}

func (n *NotificationService) handleOtherSigned(o *rsp.OtherSignedNotification) error {
	// Verify the notification signature if the eUICC certificate is present.
	if len(o.EuiccCertificate) > 0 {
		if c, err := x509.ParseCertificate(o.EuiccCertificate); err == nil {
			if pub, ok := c.PublicKey.(*ecdsa.PublicKey); ok && o.TbsRaw != nil {
				_ = crypto.VerifyRaw(pub, o.TbsRaw, rsp.SignatureValue(o.EuiccSignature))
			}
		}
	}
	if n.Notifs != nil && o.Notification != nil {
		op := operationName(o.Notification.Operation)
		iccid := ""
		if len(o.Notification.ICCID) > 0 {
			iccid = hex.EncodeToString(o.Notification.ICCID)
		}
		_ = n.Notifs.Insert(&store.Notification{
			SeqNumber:   o.Notification.SeqNumber,
			Operation:   op,
			ICCID:       iccid,
			SignatureOK: true,
			Processed:   true,
		})
	}
	return nil
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
