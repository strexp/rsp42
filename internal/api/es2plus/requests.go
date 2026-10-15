// ES2+ request and response types (SGP.22 §6.5.2).

package es2plus

import (
	"encoding/json"

	"rsp42/internal/api/common"
)

type downloadOrderReq struct {
	Header      common.RequestHeader `json:"header"`
	EID         string               `json:"eid"`
	ICCID       string               `json:"iccid"`
	ProfileType string               `json:"profileType"`
}

type confirmOrderReq struct {
	Header           common.RequestHeader `json:"header"`
	ICCID            string               `json:"iccid"`
	EID              string               `json:"eid"`
	MatchingID       string               `json:"matchingId"`
	ConfirmationCode string               `json:"confirmationCode"`
	SMDSAddress      string               `json:"smdsAddress"`
	// ReleaseFlag is mandatory (§5.3.2 Table 25; §6.5.2.2 "required":
	// ["iccid","releaseFlag"]). A pointer distinguishes an absent member from
	// an explicit false.
	ReleaseFlag *bool `json:"releaseFlag"`
}

type cancelOrderReq struct {
	Header                      common.RequestHeader `json:"header"`
	ICCID                       string               `json:"iccid"`
	EID                         string               `json:"eid"`
	MatchingID                  string               `json:"matchingId"`
	FinalProfileStatusIndicator string               `json:"finalProfileStatusIndicator"`
}

type releaseProfileReq struct {
	Header common.RequestHeader `json:"header"`
	ICCID  string               `json:"iccid"`
}

// AcrRequest / AcrResponse are the confirm/ACR hooks (Phase 10 supplies these).
type AcrRequest struct {
	EID   string          `json:"eid"`
	ICCID string          `json:"iccid"`
	Data  json.RawMessage `json:"-"`
}

// AcrResponse is the operator's response to handleAcrRequest.
type AcrResponse struct {
	Header common.HeaderResponse `json:"header"`
}
