package es11

import "rsp42/internal/service"

// The ES11 handler declares the seam it uses, so it does not depend on the
// concrete service (internal/api/admin uses the same pattern).

// DS is the SM-DS Common Mutual Authentication entry point.
type DS interface {
	Initiate(euiccChallenge, euiccInfo1 []byte, address string) (*service.InitiateResult, error)
	AuthenticateClient(transactionID string, authenticateServerResponse []byte) (*service.DSAuthResult, error)
}

// The concrete service must keep satisfying the seam.
var _ DS = (*service.DSService)(nil)
