package es2plus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ProgressInfo is the payload of ES2+.HandleDownloadProgressInfo (SGP.22 §5.3.5).
type ProgressInfo struct {
	Header                  map[string]string `json:"header"`
	EID                     string            `json:"eid,omitempty"`
	ICCID                   string            `json:"iccid"`
	ProfileType             string            `json:"profileType"`
	Timestamp               string            `json:"timestamp"`
	NotificationPointID     int               `json:"notificationPointId"`
	NotificationPointStatus any               `json:"notificationPointStatus"`
	ResultData              string            `json:"resultData,omitempty"`
}

// Notification point identifiers (SGP.22 §5.3.5).
const (
	NotificationPointEligibilityCheck = 1
	NotificationPointConfirmationCode = 2
	NotificationPointDownload         = 3
	NotificationPointInstall          = 4
	NotificationPointACR              = 17
)

// CallbackClient delivers SM-DP+ -> Operator notifications.
type CallbackClient struct {
	URL         string
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
