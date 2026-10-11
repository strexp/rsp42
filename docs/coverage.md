# SGP.22 coverage

This note records which SGP.22 v2.7 functions and requirements the SM-DP+ and
SM-DS sides implement. Only the JSON binding is implemented (the ASN.1 binding
is out of scope by design).

## Server-side functions

The specification defines no other mandatory SM-DP+/SM-DS functions.

| Function | Interface | Status |
|---|---|---|
| InitiateAuthentication | ES9+ §5.6.1 | ✅ |
| GetBoundProfilePackage | ES9+ §5.6.2 | ✅ |
| AuthenticateClient | ES9+ §5.6.3 | ✅ |
| HandleNotification | ES9+ §5.6.4 | ✅ |
| CancelSession | ES9+ §5.6.5 | ✅ |
| DownloadOrder | ES2+ §5.3.1 | ✅ |
| ConfirmOrder | ES2+ §5.3.2 | ✅ |
| CancelOrder | ES2+ §5.3.3 | ✅ |
| ReleaseProfile | ES2+ §5.3.4 | ✅ |
| HandleDownloadProgressInfo (as caller) | ES2+ §5.3.5 | ✅ |
| HandleAcrRequest (as caller) | ES2+ §5.3.8 | ◐ metadata/point-17 done; active caller call pending |
| InitiateAuthentication / AuthenticateClient | ES11 §5.8 | ✅ |
| RegisterEvent / DeleteEvent | ES12 §5.9 | ✅ |
| RegisterEvent / DeleteEvent (cascade) | ES15 §5.10 | ✅ |
| Event lifecycle: register/cascade/retrieve/delete | §3.6 | ✅ |

ES10a/b/c (§5.7) are LPA↔eUICC, and ES6 is Operator↔eUICC; both are out of
scope. §5.3.6/§5.3.7 are VOID in v2.7.

## Cross-cutting requirements

| Requirement | SGP.22 | Status |
|---|---|---|
| CMAE (eUICC ↔ server) | §3.1.2 | ✅ |
| Profile lifecycle state machine | §3.1.6 Table 6b | ✅ |
| BPP generation (SCP03t / BSP) incl. PPK | §2.5.4 / §5.5 / Annex G | ✅ |
| Confirmation code (`hashCc`) | §2.2 | ✅ |
| Notification handling (install/enable/disable/delete) | §3.5 | ✅ |
| Certificate chain, role OIDs, EUM nameConstraints/EIN | §4.5.2 | ✅ (expiry checked; CRL out of scope) |
| SAIP personalization (ICCID/IMSI/K/OPc/PIN/PUK/ADM/SPN/…) | §5.5.3 / SAIP | ◐ common params; full template table + GFSTE recompute pending |
| Activation Code Retrieval (ACR) | §4.9 | ◐ response metadata; ES2+ caller-side pending |
| Profile Policy Rules (pprIds) | §5.3 | ◐ field present, not populated from orders |
| `otherCertsInChain` | §6.5.2 | ✗ (optional) |
| CRL download / strong CRL checks | §3.5.5 | ✗ (registered risk; interface reserved) |

Legend: ✅ implemented, ◐ partial, ✗ not implemented.

## Notable spec deviations (documented risks)

- **JSON binding only**; `application/x-gsma-rsp-asn1` is not implemented.
- **No online CRL/OCSP**; expiry is validated, revocation is not.
- **AUTOMATIC TAGS** encoding of a few untagged fields (`SmdpSigned2.ccRequiredFlag`,
  `NotificationMetadata.notificationAddress`) follows the common toolchain
  bindings rather than strict X.680 auto-tagging; this is verified by the golden
  vectors in the `internal/rsp` tests.
