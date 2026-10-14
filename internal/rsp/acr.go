package rsp

import (
	"errors"
	"fmt"
)

// ErrACRRefused is the sentinel for "the Operator explicitly refused an
// Activation Code Retrieval". A refusal is a business decision, so it must not
// be retried; transport failures must be (see ACRRefusedError).
var ErrACRRefused = errors.New("rsp: activation code retrieval refused")

// ACRRefusedError reports an ES2+.HandleAcrRequest answer of Failed, carrying
// the SGP.22 status code the Operator returned (spec §5.3.8 Table 32e:
// 8.2.1/1.2 "Profile ICCID Not Allowed").
type ACRRefusedError struct {
	SubjectCode string
	ReasonCode  string
	Message     string
}

// Error implements the error interface.
func (e *ACRRefusedError) Error() string {
	switch {
	case e.SubjectCode == "" && e.Message != "":
		return "rsp: activation code retrieval refused: " + e.Message
	case e.SubjectCode == "":
		return "rsp: activation code retrieval refused"
	default:
		return fmt.Sprintf("rsp: activation code retrieval refused: %s/%s: %s", e.SubjectCode, e.ReasonCode, e.Message)
	}
}

// Is reports membership of the ErrACRRefused sentinel so callers can use
// errors.Is even when the status details are lost in wrapping.
func (e *ACRRefusedError) Is(target error) bool { return target == ErrACRRefused }
