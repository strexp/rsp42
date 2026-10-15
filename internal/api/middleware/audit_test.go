package middleware

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAuditFunction pins the path -> function reduction used by the audit
// middleware: the RSP interfaces name the invoked function in the last path
// segment (so `GET /audit?function=downloadOrder` matches and groupBy=function
// groups by function rather than by path), the ASN.1 binding uses one generic
// path for every function and therefore keeps its path (its handler names the
// function on the request scope instead), and the management API keeps its path.
func TestAuditFunction(t *testing.T) {
	for path, want := range map[string]string{
		"/gsma/rsp2/es2plus/downloadOrder":          "downloadOrder",
		"/gsma/rsp2/es2plus/confirmOrder":           "confirmOrder",
		"/gsma/rsp2/es9plus/getBoundProfilePackage": "getBoundProfilePackage",
		"/gsma/rsp2/es11/authenticateClient":        "authenticateClient",
		"/gsma/rsp2/es12/registerEvent":             "registerEvent",
		"/gsma/rsp2/es15/registerEvent":             "registerEvent",
		"/gsma/rsp2/asn1":                           "/gsma/rsp2/asn1",
		"/admin/api/v1/profiles":                    "/admin/api/v1/profiles",
		"/gsma/rsp2/es2plus":                        "/gsma/rsp2/es2plus",
		"/gsma/rsp2/es2plus/":                       "/gsma/rsp2/es2plus/",
		"/healthz":                                  "/healthz",
	} {
		require.Equal(t, want, auditFunction(path), path)
	}
}
