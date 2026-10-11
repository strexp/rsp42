package service

import (
	"encoding/hex"
	"strings"

	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// CancelSession implements ES9+.CancelSession (SGP.22 §5.6.5).
func (c *CMAE) CancelSession(transactionID string, cancelSessionResponse []byte) (string, int64, error) {
	req, err := rsp.DecodeCancelSessionRequestEs9(cancelSessionResponse)
	if err != nil {
		return "", 0, rsp.CodeUnknownTransaction.Status(err.Error())
	}
	if !strings.EqualFold(hex.EncodeToString(req.TransactionID), transactionID) {
		return "", 0, rsp.CodeUnknownTransaction.Status("transactionId mismatch")
	}
	reason := req.Reason
	if sess, err := c.Sessions.Get(transactionID); err == nil && sess.ProfileID != 0 {
		if p, err := c.Profiles.GetByID(sess.ProfileID); err == nil {
			switch reason {
			case 1, 2: // postponed, timeout: keep the profile released
			default:
				if p.State == store.StateReleased || p.State == store.StateDownloaded {
					p.State = store.StateError
					p.ErrorReason = "cancelSession"
					_ = c.Profiles.Update(p)
				}
			}
		}
	}
	_ = c.Sessions.Delete(transactionID)
	return transactionID, reason, nil
}
