package rsp

import "fmt"

// StatusCode is a SGP.22 status code (subjectCode/reasonCode pair plus optional
// subjectIdentifier and message), as carried in functionExecutionStatus.
type StatusCode struct {
	SubjectCode       string
	ReasonCode        string
	SubjectIdentifier string
	Message           string
}

// Error implements the error interface.
func (s *StatusCode) Error() string {
	msg := fmt.Sprintf("%s/%s", s.SubjectCode, s.ReasonCode)
	if s.Message != "" {
		msg += ": " + s.Message
	}
	return msg
}

// NewStatus returns a status code error.
func NewStatus(subject, reason, message string) *StatusCode {
	return &StatusCode{SubjectCode: subject, ReasonCode: reason, Message: message}
}

// Commonly used status codes (SGP.22 §5.2.6 tables). This is not exhaustive;
// handlers add more as needed.
var (
	StatusUnknownTransactionID  = &StatusCode{SubjectCode: "8.10.1", ReasonCode: "3.9", Message: "Unknown TransactionID"}
	StatusInvalidCertificate    = &StatusCode{SubjectCode: "8.1.3", ReasonCode: "6.1", Message: "Invalid certificate"}
	StatusEUICCVerificationFail = &StatusCode{SubjectCode: "8.1", ReasonCode: "6.1", Message: "eUICC verification failed"}
	StatusConfirmationCodeMiss  = &StatusCode{SubjectCode: "8.2.7", ReasonCode: "6.4", Message: "Confirmation code missing or invalid"}
	StatusSMDPAddressRefused    = &StatusCode{SubjectCode: "8.8.1", ReasonCode: "3.8", Message: "Invalid SM-DP+ address"}
	StatusCIPKNotSupported      = &StatusCode{SubjectCode: "8.8.2", ReasonCode: "3.1", Message: "Requested CI key not supported"}
	StatusNoEligibleProfile     = &StatusCode{SubjectCode: "8.2.6", ReasonCode: "3.8", Message: "No eligible profile"}
)

// Code is a named subjectCode/reasonCode pair from SGP.22 §5.2.6. Functions
// return Code.Status(message) to attach an interface-appropriate message.
type Code struct {
	Subject string
	Reason  string
}

// Status builds a StatusCode for this subject/reason pair.
func (c Code) Status(message string) *StatusCode {
	return &StatusCode{SubjectCode: c.Subject, ReasonCode: c.Reason, Message: message}
}

// Named status codes used across the ES2+/ES9+/ES11/ES12 interfaces.
var (
	CodeInvalidRequest      = Code{"8.1", "1.2"}
	CodeVerificationFailed  = Code{"8.1", "6.1"}
	CodeCertChainFailed     = Code{"8.1.3", "6.1"}
	CodeEIDNotPermitted     = Code{"8.1.4", "6.1"}
	CodeProfileLoadFailed   = Code{"8.2", "3.7"}
	CodeInputRefused        = Code{"8.2.1", "1.2"}
	CodeProfileNotFound     = Code{"8.2.5", "3.9"}
	CodeProfileNotEligible  = Code{"8.2.6", "3.8"}
	CodeAllocateFailed      = Code{"8.2.1", "3.8"}
	CodeProfileUpdateFailed = Code{"8.2.6", "3.7"}
	CodeInvalidTransition   = Code{"8.2.6", "3.5"}
	CodeConfirmationCode    = Code{"8.2.7", "6.4"}
	CodeChallengeInvalid    = Code{"8.8.1", "1.2"}
	CodeSMDPAddress         = Code{"8.8.1", "3.8"}
	CodeCIUnsupported       = Code{"8.8.2", "3.1"}
	CodeUnsupportedCurve    = Code{"8.8.5", "4.10"}
	CodeES12BadRequest      = Code{"8.9", "1.2"}
	CodeES12Upstream        = Code{"8.9", "5.1"}
	CodeDSChallengeInvalid  = Code{"8.9.1", "1.2"}
	CodeDSAddress           = Code{"8.9.1", "3.8"}
	CodeDSCIUnsupported     = Code{"8.9.2", "3.1"}
	CodeDSAuthFailed        = Code{"8.9.3", "3.1"}
	CodeEventIDInUse        = Code{"8.9.5", "3.3"}
	CodeEventNotFound       = Code{"8.9.5", "3.9"}
	CodeUnknownTransaction  = Code{"8.10.1", "3.9"}
)
