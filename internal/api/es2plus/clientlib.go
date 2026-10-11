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

// Call performs one ES2+ function call and decodes the response into out.
func (c *Client) Call(ctx context.Context, function string, req map[string]any, out any) error {
	body := map[string]any{
		"header": map[string]any{
			"functionRequesterIdentifier": c.RequesterID,
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

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
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

// StatusError returns an error when the response header indicates failure.
func (h statusHeader) StatusError() error {
	if h.OK() {
		return nil
	}
	d := h.FunctionExecutionStatus.StatusCodeData
	if d == nil {
		return fmt.Errorf("es2plus: status %s", h.FunctionExecutionStatus.Status)
	}
	return fmt.Errorf("es2plus: %s/%s: %s", d.SubjectCode, d.ReasonCode, d.Message)
}

// DownloadOrder issues ES2+.DownloadOrder.
func (c *Client) DownloadOrder(ctx context.Context, eid, iccid, profileType string) (*DownloadOrderResponse, error) {
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
	if err := c.Call(ctx, "downloadOrder", req, &resp); err != nil {
		return nil, err
	}
	if err := resp.Header.StatusError(); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ConfirmOrder issues ES2+.ConfirmOrder.
func (c *Client) ConfirmOrder(ctx context.Context, req ConfirmOrderRequest) (*ConfirmOrderResponse, error) {
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
	if err := c.Call(ctx, "confirmOrder", m, &resp); err != nil {
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
	if err := c.Call(ctx, "cancelOrder", m, &resp); err != nil {
		return err
	}
	return resp.Header.StatusError()
}

// ReleaseProfile issues ES2+.ReleaseProfile.
func (c *Client) ReleaseProfile(ctx context.Context, iccid string) error {
	var resp struct {
		Header statusHeader `json:"header"`
	}
	if err := c.Call(ctx, "releaseProfile", map[string]any{"iccid": iccid}, &resp); err != nil {
		return err
	}
	return resp.Header.StatusError()
}
