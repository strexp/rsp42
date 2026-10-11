package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SMDSCClient is the SM-DP+ (or cascade) ES12 client used to register and
// delete events at an SM-DS (SGP.22 §5.9).
type SMDSCClient struct {
	BaseURL     string // e.g. https://testrootsmds.example.com:9444
	RequesterID string
	HTTP        *http.Client
	MaxAttempts int
	Backoff     func(attempt int) time.Duration
}

// NewSMDSCClient builds an ES12 client.
func NewSMDSCClient(baseURL, requesterID string, hc *http.Client) *SMDSCClient {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &SMDSCClient{BaseURL: baseURL, RequesterID: requesterID, HTTP: hc, MaxAttempts: 3,
		Backoff: func(a int) time.Duration { return time.Duration(1<<uint(a)) * time.Second }}
}

// ES12Error is a failure reported by an SM-DS ES12 function.
type ES12Error struct {
	SubjectCode string `json:"subjectCode"`
	ReasonCode  string `json:"reasonCode"`
	Message     string `json:"message"`
}

func (e *ES12Error) Error() string {
	return fmt.Sprintf("es12: %s/%s: %s", e.SubjectCode, e.ReasonCode, e.Message)
}

// IsNotFound reports whether the error is a "not found" (8.9.5/3.9) condition.
func (e *ES12Error) IsNotFound() bool { return e.ReasonCode == "3.9" }

// IsAlreadyInUse reports whether the error is "Already in use" (8.9.5/3.3).
func (e *ES12Error) IsAlreadyInUse() bool { return e.ReasonCode == "3.3" }

type es12Response struct {
	Header struct {
		FunctionExecutionStatus struct {
			Status         string     `json:"status"`
			StatusCodeData *ES12Error `json:"statusCodeData"`
		} `json:"functionExecutionStatus"`
	} `json:"header"`
}

func (c *SMDSCClient) call(ctx context.Context, function string, body map[string]any) error {
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
		err := c.callOnce(ctx, function, body)
		if err == nil {
			return nil
		}
		lastErr = err
		// Do not retry protocol-level failures (business status codes).
		var esErr *ES12Error
		if errors.As(err, &esErr) {
			return err
		}
	}
	return lastErr
}

func (c *SMDSCClient) callOnce(ctx context.Context, function string, body map[string]any) error {
	body["header"] = map[string]any{
		"functionRequesterIdentifier": c.RequesterID,
		"functionCallIdentifier":      fmt.Sprintf("ES12-%d", time.Now().UnixNano()),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/gsma/rsp2/es12/"+function, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("es12: unexpected HTTP %d", resp.StatusCode)
	}
	var out es12Response
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("es12: decode: %w", err)
	}
	status := out.Header.FunctionExecutionStatus.Status
	if status == "Executed-Success" || status == "Executed-WithWarning" {
		return nil
	}
	if out.Header.FunctionExecutionStatus.StatusCodeData != nil {
		return out.Header.FunctionExecutionStatus.StatusCodeData
	}
	return fmt.Errorf("es12: status %s", status)
}

// Register registers an event.
func (c *SMDSCClient) Register(eid, rspServerAddress, eventID string, forwardingIndicator bool) error {
	err := c.call(context.Background(), "registerEvent", map[string]any{
		"eid":                 eid,
		"rspServerAddress":    rspServerAddress,
		"eventId":             eventID,
		"forwardingIndicator": forwardingIndicator,
	})
	var e *ES12Error
	if errors.As(err, &e) && e.IsAlreadyInUse() {
		return nil // idempotent: already registered
	}
	return err
}

// Delete deletes an event.
func (c *SMDSCClient) Delete(eid, eventID string) error {
	return c.call(context.Background(), "deleteEvent", map[string]any{
		"eid":     eid,
		"eventId": eventID,
	})
}

// IsNotFound reports whether err is a "not found" condition.
func (c *SMDSCClient) IsNotFound(err error) bool {
	var e *ES12Error
	return errors.As(err, &e) && e.IsNotFound()
}
