package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"rsp42/internal/metrics"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// ACROperator calls the Operator's ES2+.HandleAcrRequest (SGP.22 §5.3.8). The
// request body carries only the ICCID (§5.3.8 Table 32d / §6.5.2.20), so no
// profile details cross the interface.
type ACROperator interface {
	HandleAcrRequest(ctx context.Context, iccid string) error
}

// ACRChecker adapts an ACROperator into the SM-DP+ ACR hook
// (`CMAE.ACRCheck`). It bounds the whole confirmation (including the client's
// retries) with a timeout so an unreachable Operator cannot stall the LPA's
// authenticateClient, and records the outcome for the operator dashboard.
type ACRChecker struct {
	Operator ACROperator
	// Timeout bounds the whole confirmation call, retries included. Zero
	// disables the extra bound (the caller's context still applies).
	Timeout time.Duration
	Metrics *metrics.Registry
	Audit   *store.AuditRepo
	Log     *slog.Logger
}

// ACR outcome labels.
const (
	ACROutcomeAllowed = "allowed"
	ACROutcomeRefused = "refused"
	ACROutcomeError   = "error"
)

// Check confirms the Activation Code Retrieval of a profile with the Operator.
// A nil profile (or an empty ICCID) is a programming error, not an Operator
// decision, and is reported as such.
func (c *ACRChecker) Check(ctx context.Context, p *store.Profile) error {
	if c.Operator == nil {
		return errors.New("service: ACR operator not configured")
	}
	if p == nil || p.ICCID == "" {
		return errors.New("service: ACR confirmation requires a profile")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	err := c.Operator.HandleAcrRequest(ctx, p.ICCID)
	outcome := ACROutcomeAllowed
	switch {
	case err == nil:
	case errors.Is(err, rsp.ErrACRRefused):
		outcome = ACROutcomeRefused
	default:
		outcome = ACROutcomeError
	}

	if c.Metrics != nil {
		c.Metrics.Inc("rsp42_acr_requests_total", map[string]string{
			"tenant": p.TenantID, "outcome": outcome,
		})
	}
	c.record(p, outcome, err)
	if err != nil && c.Log != nil {
		c.Log.Warn("ES2+ HandleAcrRequest", "iccid", p.ICCID, "tenant", p.TenantID, "outcome", outcome, "err", err)
	}
	return err
}

// record writes an audit row for the outbound ACR call. A refused retrieval is
// an Operator decision and must be traceable per profile.
func (c *ACRChecker) record(p *store.Profile, outcome string, err error) {
	if c.Audit == nil {
		return
	}
	detail := map[string]any{"iccid": p.ICCID, "outcome": outcome}
	if err != nil {
		detail["error"] = err.Error()
	}
	var subjectCode, reasonCode string
	var refused *rsp.ACRRefusedError
	if errors.As(err, &refused) {
		subjectCode, reasonCode = refused.SubjectCode, refused.ReasonCode
	}
	blob, _ := json.Marshal(detail)
	auditOutcome := "Executed-Success"
	status := ""
	if err != nil {
		auditOutcome = "Failed"
		if subjectCode != "" {
			status = fmt.Sprintf("%s/%s", subjectCode, reasonCode)
		}
	}
	_ = c.Audit.Insert(&store.AuditEntry{
		TenantID: p.TenantID, Interface: "es2p", Function: "handleAcrRequest",
		Subject: p.ICCID, Outcome: auditOutcome, StatusCode: status, DetailJSON: string(blob),
	})
}
