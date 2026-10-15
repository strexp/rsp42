package service

import (
	"encoding/hex"
	"fmt"
	"strings"

	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// CancelSession implements ES9+.CancelSession over the ASN.1 binding (SGP.22
// §5.6.5). The request is the §6.6.2.5 wrapper
// CancelSessionRequestEs9 ::= [65] SEQUENCE { transactionId, cancelSessionResponse }.
func (c *CMAE) CancelSession(transactionID string, cancelSessionRequestEs9 []byte) (string, int64, error) {
	req, err := rsp.DecodeCancelSessionRequestEs9(cancelSessionRequestEs9)
	if err != nil {
		return "", 0, rsp.CodeUnknownTransaction.Status(err.Error())
	}
	if !strings.EqualFold(hex.EncodeToString(req.TransactionID), transactionID) {
		return "", 0, rsp.CodeUnknownTransaction.Status("transactionId mismatch")
	}
	c.applyCancelSession(transactionID, req.Reason)
	return transactionID, req.Reason, nil
}

// CancelSessionJSON implements ES9+.CancelSession over the JSON binding. The
// JSON request carries the bare ES10b CancelSessionResponse (SGP.22 §6.5.2.10:
// "base64 encoded binary data containing CancelSessionResponse data object
// defined in Section 5.7.14"), i.e. the BF41 CHOICE, not the §6.6.2.5
// CancelSessionRequestEs9 wrapper.
func (c *CMAE) CancelSessionJSON(transactionID string, cancelSessionResponse []byte) (string, int64, error) {
	ok, code, err := rsp.DecodeCancelSessionResponse(cancelSessionResponse)
	if err != nil {
		return "", 0, rsp.CodeUnknownTransaction.Status(err.Error())
	}
	if ok == nil || ok.Signed == nil {
		// The ES10b error alternative (§5.7.14): invalidTransactionId(5) or
		// undefinedError(127).
		if code == 5 {
			return "", 0, rsp.CodeUnknownTransaction.Status("invalidTransactionId")
		}
		return "", 0, rsp.CodeVerificationFailed.Status(
			fmt.Sprintf("cancelSessionResponseError %d", code))
	}
	if !strings.EqualFold(hex.EncodeToString(ok.Signed.TransactionID), transactionID) {
		return "", 0, rsp.CodeUnknownTransaction.Status("transactionId mismatch")
	}
	c.applyCancelSession(transactionID, ok.Signed.Reason)
	return transactionID, ok.Signed.Reason, nil
}

// applyCancelSession is the state-mutation half shared by both bindings. A
// reason that terminates the download order (anything but postponed/timeout)
// moves a released/downloaded Profile to Error (SGP.22 §5.6.5 and §5.7.14);
// the session is always discarded.
func (c *CMAE) applyCancelSession(transactionID string, reason int64) {
	if sess, err := c.Deps.Sessions.Get(transactionID); err == nil && sess.ProfileID != 0 {
		if p, err := c.Deps.Profiles.GetByID(sess.ProfileID); err == nil {
			switch reason {
			case 1, 2: // postponed, timeout: keep the profile released
			default:
				if p.State == store.StateReleased || p.State == store.StateDownloaded {
					p.State = store.StateError
					p.ErrorReason = "cancelSession"
					_ = c.Deps.Profiles.Update(p)
				}
			}
		}
	}
	_ = c.Deps.Sessions.Delete(transactionID)
}
