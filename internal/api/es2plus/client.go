package es2plus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
)

// ProgressInfo is the payload of ES2+.HandleDownloadProgressInfo (SGP.22 §5.3.5).
// TenantID/ExternalRef/MatchingID are rsp42 additions on this outbound
// notification (the function is SM-DP+ -> Operator, so it does not have to obey
// the ES2+ input schema).
type ProgressInfo struct {
	Header                  map[string]string `json:"header"`
	EID                     string            `json:"eid,omitempty"`
	ICCID                   string            `json:"iccid"`
	ProfileType             string            `json:"profileType"`
	Timestamp               string            `json:"timestamp"`
	NotificationPointID     int               `json:"notificationPointId"`
	NotificationPointStatus any               `json:"notificationPointStatus"`
	ResultData              string            `json:"resultData,omitempty"`
	TenantID                string            `json:"tenantId,omitempty"`
	ExternalRef             string            `json:"externalRef,omitempty"`
	MatchingID              string            `json:"matchingId,omitempty"`
}

// Notification point identifiers (SGP.22 §5.3.5): 1 = eligibility/authorisation
// check, 2 = confirmation code, 3 = download, 4 = installation result,
// 17 = activation code retrieval.
const (
	NotificationPointEligibilityCheck = 1
	NotificationPointConfirmationCode = 2
	NotificationPointDownload         = 3
	NotificationPointInstall          = 4
	NotificationPointACR              = 17
)

// CallbackClient delivers SM-DP+ -> Operator notifications.
type CallbackClient struct {
	URL string
	// ACRURL, when set, is the Operator's ES2+.HandleAcrRequest endpoint.
	ACRURL      string
	RequesterID string
	HTTP        *http.Client
	MaxAttempts int
	Backoff     func(attempt int) time.Duration
}

// NewCallbackClient builds a callback client.
func NewCallbackClient(url, requesterID string, hc *http.Client) *CallbackClient {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &CallbackClient{URL: url, RequesterID: requesterID, HTTP: hc, MaxAttempts: 3,
		Backoff: func(a int) time.Duration { return time.Duration(1<<uint(a)) * time.Second }}
}

// Post delivers one already-serialized notification body to url in a single
// attempt. A 204 or 200 response is treated as success.
func (c *CallbackClient) Post(ctx context.Context, url string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("es2plus: callback status %d", resp.StatusCode)
}

// ErrACRNotConfigured is returned when no Operator ACR endpoint is configured.
var ErrACRNotConfigured = errors.New("es2plus: no ACR URL configured")

// HandleAcrRequest calls the Operator's ES2+.HandleAcrRequest (SGP.22 §5.3.8) to
// confirm the Activation Code Retrieval of a profile.
//
// The request body carries only the ICCID, as the spec's schema for this
// function mandates (§5.3.8 Table 32d / §6.5.2.20) — no private body extension.
// Transport and HTTP failures are retried with backoff; an explicit refusal by
// the Operator (Failed, typically 8.2.1/1.2) is a business decision and returns
// immediately as an *rsp.ACRRefusedError.
func (c *CallbackClient) HandleAcrRequest(ctx context.Context, iccid string) error {
	if c.ACRURL == "" {
		return ErrACRNotConfigured
	}
	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 && c.Backoff != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.Backoff(i - 1)):
			}
		}
		err := c.postACR(ctx, iccid)
		if err == nil {
			return nil
		}
		if errors.Is(err, rsp.ErrACRRefused) {
			return err // the Operator answered: do not retry
		}
		lastErr = err
	}
	return lastErr
}

// postACR performs a single ES2+.HandleAcrRequest call.
func (c *CallbackClient) postACR(ctx context.Context, iccid string) error {
	req := struct {
		Header common.RequestHeader `json:"header"`
		ICCID  string               `json:"iccid"`
	}{
		Header: common.RequestHeader{
			FunctionRequesterIdentifier: c.RequesterID,
			FunctionCallIdentifier:      fmt.Sprintf("ACR-%d", time.Now().UnixNano()),
		},
		ICCID: iccid,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ACRURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("es2plus: handleAcrRequest status %d", resp.StatusCode)
	}
	var out common.HeaderResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	status := out.Header.FunctionExecutionStatus.Status
	if status == common.StatusExecutedSuccess || status == common.StatusExecutedWithWarning {
		return nil
	}
	d := out.Header.FunctionExecutionStatus.StatusCodeData
	refused := &rsp.ACRRefusedError{Message: string(status)}
	if d != nil {
		refused.SubjectCode, refused.ReasonCode, refused.Message = d.SubjectCode, d.ReasonCode, d.Message
	}
	return refused
}

// HandleDownloadProgressInfo posts a notification, retrying with backoff.
func (c *CallbackClient) HandleDownloadProgressInfo(ctx context.Context, info ProgressInfo) error {
	if c.URL == "" {
		return fmt.Errorf("es2plus: no callback URL configured")
	}
	if info.Header == nil {
		info.Header = map[string]string{
			"functionRequesterIdentifier": c.RequesterID,
			"functionCallIdentifier":      fmt.Sprintf("CB-%d", time.Now().UnixNano()),
		}
	}
	raw, err := json.Marshal(info)
	if err != nil {
		return err
	}
	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 && c.Backoff != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.Backoff(i - 1)):
			}
		}
		if err := c.Post(ctx, c.URL, raw); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}
