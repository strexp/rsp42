package es9plus

import (
	"context"

	"rsp42/internal/service"
)

// The ES9+ handler declares the seams it uses: the Common Mutual Authentication
// entry point and the notification sink. Defining them here (rather than taking
// *service.CMAE / *service.NotificationService) lets the handlers be exercised
// without the concrete services, matching the pattern of internal/api/admin.

// CMAE is the SM-DP+ Common Mutual Authentication entry point.
type CMAE interface {
	Initiate(euiccChallenge, euiccInfo1 []byte, smdpAddress string) (*service.InitiateResult, error)
	AuthenticateClient(ctx context.Context, transactionID string, authenticateServerResponse []byte) (*service.AuthenticateResult, error)
	GetBoundProfilePackage(transactionID string, prepareDownloadResponse []byte) (*service.GetBoundProfilePackageResult, error)
	CancelSession(transactionID string, cancelSessionRequestEs9 []byte) (string, int64, error)
	CancelSessionJSON(transactionID string, cancelSessionResponse []byte) (string, int64, error)
}

// Notifier processes the pending notification an LPA carries in
// HandleNotification.
type Notifier interface {
	HandlePendingNotification(ctx context.Context, raw []byte) error
}

// The concrete services must keep satisfying the seams.
var (
	_ CMAE     = (*service.CMAE)(nil)
	_ Notifier = (*service.NotificationService)(nil)
)
