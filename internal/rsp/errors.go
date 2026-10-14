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
	CodeInvalidRequest     = Code{"8.1", "1.2"}
	CodeVerificationFailed = Code{"8.1", "6.1"}
	CodeCertChainFailed    = Code{"8.1.3", "6.1"}
	CodeEIDNotPermitted    = Code{"8.1.4", "6.1"}
	CodeProfileLoadFailed  = Code{"8.2", "3.7"}
	CodeInputRefused       = Code{"8.2.1", "1.2"}
	CodeProfileNotEligible = Code{"8.2.6", "3.8"}
	// CodeAllocateFailed is a generic DownloadOrder allocation failure
	// (Profile / Execution Error). Pool or quota exhaustion uses the more
	// specific CodeNoMoreProfileAvailable, and an ICCID conflict uses
	// CodeICCIDInUse (C3).
	CodeAllocateFailed = Code{"8.2", "4.2"}
	// CodeProfileUpdateFailed is a failed Profile/order write (Profile /
	// Execution Error). The previous 8.2.6/3.7 mixed the Matching ID subject
	// with an inapplicable reason (C4).
	CodeProfileUpdateFailed = Code{"8.2", "4.2"}
	// CodeNoMoreProfileAvailable is Table 24's 8.2.5/3.7: no Profile of the
	// requested Profile Type is available (pool/quota exhaustion).
	CodeNoMoreProfileAvailable = Code{"8.2.5", "3.7"}
	// CodeICCIDInUse is 8.2.1/3.3: the Profile identified by the ICCID is not
	// available (already in use, blocked or otherwise not issuable).
	CodeICCIDInUse         = Code{"8.2.1", "3.3"}
	CodeInvalidTransition  = Code{"8.2.6", "3.5"}
	CodeConfirmationCode   = Code{"8.2.7", "6.4"}
	CodeChallengeInvalid   = Code{"8.8.1", "1.2"}
	CodeSMDPAddress        = Code{"8.8.1", "3.8"}
	CodeCIUnsupported      = Code{"8.8.2", "3.1"}
	CodeUnsupportedCurve   = Code{"8.8.5", "4.10"}
	CodeES12BadRequest     = Code{"8.9", "1.2"}
	CodeES12Upstream       = Code{"8.9", "5.1"}
	CodeDSChallengeInvalid = Code{"8.9.1", "1.2"}
	CodeDSAddress          = Code{"8.9.1", "3.8"}
	CodeDSCIUnsupported    = Code{"8.9.2", "3.1"}
	CodeDSAuthFailed       = Code{"8.9.3", "3.1"}
	CodeEventIDInUse       = Code{"8.9.5", "3.3"}
	CodeEventNotFound      = Code{"8.9.5", "3.9"}
	CodeUnknownTransaction = Code{"8.10.1", "3.9"}

	// CodeProfileVersionNotSupported is returned when no UPP template is
	// compatible with the eUICC's advertised SAIP versions (N12). SGP.22 has no
	// dedicated code for this condition, so 8.2.6/3.8 is used with a readable
	// message; it deliberately does not reuse 8.8.5/4.10 (unsupported curve).
	CodeProfileVersionNotSupported = Code{"8.2.6", "3.8"}

	// ES2+ argument/authorisation codes (SGP.22 §5.2.6, Tables 23/24/26).
	//
	// CodeInvalidAssociation is returned by ConfirmOrder when its EID does not
	// match the EID of the DownloadOrder (§5.3.2).
	CodeInvalidAssociation = Code{"8.1.1", "3.10"}
	// CodeMandatoryElementMissing is returned when a mandatory request element
	// (e.g. iccid) is absent.
	CodeMandatoryElementMissing = Code{"8.1.1", "2.2"}
	// CodeICCIDUnknown is returned when the ICCID is not known to the SM-DP+
	// (§5.3.1 8.2.1/3.9). It is deliberately distinct from a Profile Type
	// problem so the operator can branch correctly.
	CodeICCIDUnknown = Code{"8.2.1", "3.9"}
	// CodeProfileTypeUnknown is returned when the requested Profile Type cannot
	// be resolved (§5.3.1 8.2.5/3.9).
	CodeProfileTypeUnknown = Code{"8.2.5", "3.9"}
	// CodeProfileTypeNotAllowed is returned when the caller may not use the
	// requested Profile Type / template (§5.3.1 8.2.5/1.2, authorisation).
	CodeProfileTypeNotAllowed = Code{"8.2.5", "1.2"}
	// CodeACRNotAllowed is the ES2+.HandleAcrRequest-specific refusal code
	// (§5.3.8 Table 32e: Profile ICCID Not Allowed). It shares the
	// 8.2.1/1.2 pair with CodeInputRefused but names the ACR semantics.
	CodeACRNotAllowed = Code{"8.2.1", "1.2"}
	// CodeProfileNotFound is kept for ES9+ internal use where the spec's
	// "Profile not found" wording applies.
	CodeProfileNotFound = Code{"8.2.5", "3.9"}
)
