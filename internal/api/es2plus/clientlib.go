package es2plus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Client is the ES2+ client library used by operator systems to drive the
// SM-DP+ (DownloadOrder / ConfirmOrder / CancelOrder / ReleaseProfile).
type Client struct {
	BaseURL     string
	RequesterID string
	HTTP        *http.Client
	funcID      atomic.Int64
}

// NewClient builds an ES2+ client. When hc is nil a default client is used.
func NewClient(baseURL, requesterID string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{BaseURL: baseURL, RequesterID: requesterID, HTTP: hc}
}

func (c *Client) nextCallID() string {
	n := c.funcID.Add(1)
	return fmt.Sprintf("FCI-%d-%d", time.Now().Unix(), n)
}

// CallOptions overrides per-call client settings. SGP.22 §6.2 allows additional
// HTTP header fields, so the idempotency key is carried out of band.
type CallOptions struct {
	// Requester overrides the client-level functionRequesterIdentifier. This is
	// what lets one client act for several operators (and therefore several
	// tenants) without sharing mutable state.
	Requester string
	// IdempotencyKey sets the Idempotency-Key header for the write functions
	// whose resend semantics SGP.22 does not define.
	IdempotencyKey string
	// Headers adds further request headers.
	Headers map[string]string
}

// Call performs one ES2+ function call and decodes the response into out.
func (c *Client) Call(ctx context.Context, function string, req map[string]any, out any) error {
	return c.CallWithOptions(ctx, function, req, out, CallOptions{})
}

// CallWithOptions is Call with per-call overrides.
func (c *Client) CallWithOptions(ctx context.Context, function string, req map[string]any, out any, opts CallOptions) error {
	requester := c.RequesterID
	if opts.Requester != "" {
		requester = opts.Requester
	}
	body := map[string]any{
		"header": map[string]any{
			"functionRequesterIdentifier": requester,
			"functionCallIdentifier":      c.nextCallID(),
		},
	}
	for k, v := range req {
		body[k] = v
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := c.BaseURL + "/gsma/rsp2/es2plus/" + function
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if opts.IdempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", opts.IdempotencyKey)
	}
	for k, v := range opts.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("es2plus: decode response: %w", err)
		}
	}
	return nil
}

// DownloadOrderResponse is returned by DownloadOrder.
type DownloadOrderResponse struct {
	Header statusHeader `json:"header"`
	ICCID  string       `json:"iccid"`
}

// ConfirmOrderResponse is returned by ConfirmOrder.
type ConfirmOrderResponse struct {
	Header      statusHeader `json:"header"`
	EID         string       `json:"eid"`
	MatchingID  string       `json:"matchingId"`
	SMDPAddress string       `json:"smdpAddress"`
}

type statusHeader struct {
	FunctionExecutionStatus struct {
		Status         string `json:"status"`
		StatusCodeData *struct {
			SubjectCode string `json:"subjectCode"`
			ReasonCode  string `json:"reasonCode"`
			Message     string `json:"message"`
		} `json:"statusCodeData"`
	} `json:"functionExecutionStatus"`
}

// OK reports whether the function executed successfully.
func (h statusHeader) OK() bool {
	s := h.FunctionExecutionStatus.Status
	return s == "Executed-Success" || s == "Executed-WithWarning"
}

// HTTPError is a non-2xx HTTP response (e.g. the 409 returned when an
// Idempotency-Key is reused with a different body).
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("es2plus: http %d: %s", e.StatusCode, e.Body)
}

// StatusError is a Failed ES2+ response, exposing its SGP.22 status code.
type StatusError struct {
	Status      string
	SubjectCode string
	ReasonCode  string
	Message     string
}

func (e *StatusError) Error() string {
	if e.SubjectCode == "" {
		return fmt.Sprintf("es2plus: status %s", e.Status)
	}
	return fmt.Sprintf("es2plus: %s/%s: %s", e.SubjectCode, e.ReasonCode, e.Message)
}

// IsCode reports whether the response carries the given subject/reason pair.
func (e *StatusError) IsCode(subject, reason string) bool {
	return e.SubjectCode == subject && e.ReasonCode == reason
}

// StatusError returns an error when the response header indicates failure.
func (h statusHeader) StatusError() error {
	if h.OK() {
		return nil
	}
	d := h.FunctionExecutionStatus.StatusCodeData
	if d == nil {
		return &StatusError{Status: h.FunctionExecutionStatus.Status}
	}
	return &StatusError{
		Status:      h.FunctionExecutionStatus.Status,
		SubjectCode: d.SubjectCode, ReasonCode: d.ReasonCode, Message: d.Message,
	}
}

// DownloadOrder issues ES2+.DownloadOrder.
func (c *Client) DownloadOrder(ctx context.Context, eid, iccid, profileType string) (*DownloadOrderResponse, error) {
	return c.DownloadOrderWith(ctx, eid, iccid, profileType, CallOptions{})
}

// DownloadOrderWith is DownloadOrder with per-call overrides.
func (c *Client) DownloadOrderWith(ctx context.Context, eid, iccid, profileType string, opts CallOptions) (*DownloadOrderResponse, error) {
	req := map[string]any{}
	if eid != "" {
		req["eid"] = eid
	}
	if iccid != "" {
		req["iccid"] = iccid
	}
	if profileType != "" {
		req["profileType"] = profileType
	}
	var resp DownloadOrderResponse
	if err := c.CallWithOptions(ctx, "downloadOrder", req, &resp, opts); err != nil {
		return nil, err
	}
	if err := resp.Header.StatusError(); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ConfirmOrder issues ES2+.ConfirmOrder.
func (c *Client) ConfirmOrder(ctx context.Context, req ConfirmOrderRequest) (*ConfirmOrderResponse, error) {
	return c.ConfirmOrderWith(ctx, req, CallOptions{})
}

// ConfirmOrderWith is ConfirmOrder with per-call overrides.
func (c *Client) ConfirmOrderWith(ctx context.Context, req ConfirmOrderRequest, opts CallOptions) (*ConfirmOrderResponse, error) {
	m := map[string]any{"iccid": req.ICCID, "releaseFlag": req.ReleaseFlag}
	if req.EID != "" {
		m["eid"] = req.EID
	}
	if req.MatchingID != "" {
		m["matchingId"] = req.MatchingID
	}
	if req.ConfirmationCode != "" {
		m["confirmationCode"] = req.ConfirmationCode
	}
	if req.SMDSAddress != "" {
		m["smdsAddress"] = req.SMDSAddress
	}
	var resp ConfirmOrderResponse
	if err := c.CallWithOptions(ctx, "confirmOrder", m, &resp, opts); err != nil {
		return nil, err
	}
	if err := resp.Header.StatusError(); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ConfirmOrderRequest parameterizes ConfirmOrder.
type ConfirmOrderRequest struct {
	ICCID            string
	EID              string
	MatchingID       string
	ConfirmationCode string
	SMDSAddress      string
	ReleaseFlag      bool
}

// CancelOrder issues ES2+.CancelOrder.
func (c *Client) CancelOrder(ctx context.Context, iccid, eid, matchingID, finalStatus string) error {
	return c.CancelOrderWith(ctx, iccid, eid, matchingID, finalStatus, CallOptions{})
}

// CancelOrderWith is CancelOrder with per-call overrides.
func (c *Client) CancelOrderWith(ctx context.Context, iccid, eid, matchingID, finalStatus string, opts CallOptions) error {
	m := map[string]any{"iccid": iccid}
	if eid != "" {
		m["eid"] = eid
	}
	if matchingID != "" {
		m["matchingId"] = matchingID
	}
	if finalStatus != "" {
		m["finalProfileStatusIndicator"] = finalStatus
	}
	var resp struct {
		Header statusHeader `json:"header"`
	}
	if err := c.CallWithOptions(ctx, "cancelOrder", m, &resp, opts); err != nil {
		return err
	}
	return resp.Header.StatusError()
}

// ReleaseProfile issues ES2+.ReleaseProfile.
func (c *Client) ReleaseProfile(ctx context.Context, iccid string) error {
	return c.ReleaseProfileWith(ctx, iccid, CallOptions{})
}

// ReleaseProfileWith is ReleaseProfile with per-call overrides.
func (c *Client) ReleaseProfileWith(ctx context.Context, iccid string, opts CallOptions) error {
	var resp struct {
		Header statusHeader `json:"header"`
	}
	if err := c.CallWithOptions(ctx, "releaseProfile", map[string]any{"iccid": iccid}, &resp, opts); err != nil {
		return err
	}
	return resp.Header.StatusError()
}
