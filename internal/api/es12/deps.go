package es12

import (
	es12client "rsp42/internal/client/es12"
	"rsp42/internal/service"
)

// The ES12 handler declares the seams it uses, so it does not depend on the
// concrete services (internal/api/admin uses the same pattern).

// EventRegistrar is the SM-DS event store the ES12 functions write through.
type EventRegistrar interface {
	Register(eid, rspServerAddress, eventID string, forwardingIndicator bool, callerOID string, meta es12client.EventMeta) error
	Delete(eid, eventID, callerOID string) error
}

// TenantResolver maps a caller OID to a tenant when the correlation header is
// absent.
type TenantResolver interface {
	Resolve(requester string) (tenant string, mapped bool)
}

// The concrete services must keep satisfying the seams.
var (
	_ EventRegistrar = (*service.EventService)(nil)
	_ TenantResolver = (*service.TenantResolver)(nil)
)
