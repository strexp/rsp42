package service

import (
	"context"
	"encoding/hex"
	"log/slog"
	"strings"

	"rsp42/internal/cert"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// ProgressInfo is the payload of ES2+.HandleDownloadProgressInfo (SGP.22
// §5.3.5). It is the single DTO for this outbound notification: callers fill the
// domain fields and the delivery transport (es2plus.CallbackQueue) fills Header
// and Timestamp. TenantID/ExternalRef/MatchingID are rsp42 additions (the
// function is rsp42 -> Operator, so it is not bound by the ES2+ input schema).
//
// The JSON field names, omitempty flags and field order are the on-wire
// contract (see docs/interfaces.md) and must not change.
type ProgressInfo struct {
	Header                  map[string]string `json:"header"`
	EID                     string            `json:"eid,omitempty"`
	ICCID                   string            `json:"iccid"`
	ProfileType             string            `json:"profileType"`
	Timestamp               string            `json:"timestamp"`
	NotificationPointID     int               `json:"notificationPointId"`
	NotificationPointStatus PointStatus       `json:"notificationPointStatus"`
	ResultData              string            `json:"resultData,omitempty"`
	TenantID                string            `json:"tenantId,omitempty"`
	ExternalRef             string            `json:"externalRef,omitempty"`
	MatchingID              string            `json:"matchingId,omitempty"`
}

// PointStatus is the notificationPointStatus object of a ProgressInfo payload.
// rsp42 only emits its status member.
type PointStatus struct {
	Status string `json:"status"`
}

// OperatorCallback delivers an ES2+.HandleDownloadProgressInfo notification to
// the operator. It is optional.
type OperatorCallback func(ctx context.Context, info ProgressInfo) error

// progressMeta builds the ES12 correlation metadata for a profile.
func progressMeta(p *store.Profile) EventMeta {
	if p == nil {
		return EventMeta{}
	}
	return EventMeta{Tenant: p.TenantID, ICCID: p.ICCID, MatchingID: p.MatchingID}
}

// progressFor builds a ProgressInfo from a profile; eid overrides the stored
// value when known from the session.
func progressFor(p *store.Profile, eid string, pointID int, status string) ProgressInfo {
	info := ProgressInfo{
		EID:                     eid,
		NotificationPointID:     pointID,
		NotificationPointStatus: PointStatus{Status: status},
	}
	if p != nil {
		info.TenantID = p.TenantID
		info.ExternalRef = p.ExternalRef
		info.MatchingID = p.MatchingID
		info.ICCID = p.ICCID
		if info.EID == "" {
			info.EID = p.EID
		}
	}
	return info
}

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
				if err := n.Registrar.DeleteForEID(profile.EID, progressMeta(profile)); err != nil && n.Log != nil {
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
	n.notify(ctx, progressFor(profile, eidOf(profile), 4, "Executed-Success"))
	return nil
}

// verifyPIRSignature checks euiccSignPIR over the ProfileInstallationResultData
// (BF27) using the eUICC certificate from the download session.

func (n *NotificationService) record(notif *store.Notification) {
	if n.Notifs == nil {
		return
	}
	_ = n.Notifs.Insert(notif)
}

func (n *NotificationService) notify(ctx context.Context, info ProgressInfo) {
	if n.Callback == nil {
		return
	}
	if err := n.Callback(ctx, info); err != nil && n.Log != nil {
		n.Log.Warn("operator callback failed", "point", info.NotificationPointID, "err", err)
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
