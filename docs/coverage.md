# SGP.22 coverage

This note records which SGP.22 v2.7 functions and requirements the SM-DP+ and
SM-DS sides implement. Both the JSON binding (§6.5) and the ASN.1 binding (§6.6)
are implemented; an LPA selects one per request via the `Content-Type` header.

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
| HandleAcrRequest (as caller) | ES2+ §5.3.8 | ✅ (calls the Operator when `notifications.es2p_callback.acr_url` is set) |
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
| ASN.1 binding (`RemoteProfileProvisioningRequest/Response`, `/gsma/rsp2/asn1`) | §6.6 | ✅ (hand-written; ES9+ and ES11) |
| Notification handling (install/enable/disable/delete) | §3.5 | ✅ (euiccSignPIR / euiccNotificationSignature verified; unauthenticated notifications are recorded but not acted on) |
| Certificate chain, role OIDs, EUM nameConstraints/EIN | §4.5.2 | ✅ (expiry checked; CRL out of scope) |
| Multiple CI identities (SGP.26 variants) | §4.5.2 | ✅ (`certs.identities`; selected by `euiccCiPKIdToBeUsed`) |
| SAIP personalization (ICCID/IMSI/K/OPc/PIN/PUK/ADM/SPN/PLMN/MSISDN/ACC/SdKey*/MncLen/EF patches) | §5.5.3 / SAIP | ✅ per-ICCID (DB-backed, K/OPc encrypted at rest); GP key set written to `PE-SecurityDomain`, MNC length to `EF.AD` (6FAD); mandatory-services + GFSTE list recomputed |
| UPP template registry (DB, hot-updatable) | — | ✅ (`upp_templates`; import via `admin upp import`; `profiles.allowed_saip_versions` caps the accepted SAIP baseline) |
| UPP template selection by eUICC profile version | §5.5.3 | ✅ (registry lookup by the eUICC's supported version set — `profileVersion` plus `additionalEuiccProfilePackageVersions`; order override wins; no compatible template fails cleanly with `8.2.6/3.8`) |
| SAIP profile package validation (V2.3.1 constraints) | SAIP Annex A/B, §9 | ✅ (`/upp/validate` + `/upp`: structure/order, mandatory services, AKA/service bits, PE identification, File `doNotCreate`/`fileDescriptor`, GFSTE subset of the 14 Annex B template OIDs) |
| Activation Code Retrieval (ACR) | §4.9 / §5.3.8 | ✅ response metadata (both ACR types) + caller-side Operator confirmation through `ES2+.HandleAcrRequest` (`acr_url`), refusal `8.2.1/1.2` |
| Profile Policy Rules (PPR) | §5.3 | ✅ populated from `profiles.ppr_ids`; the non-standard ES2+ `downloadOrder.pprIds` body member was removed (C1) |
| `otherCertsInChain` | §6.5.2 | ✅ parsed and chained between EUM and CI |
| CRL download / strong CRL checks | §3.5.5 | ✗ (registered risk; interface reserved) |

Legend: ✅ implemented, ◐ partial, ✗ not implemented.

## Notable spec deviations (documented risks)

- **NIST P-256 only**; the Brainpool P256r1 `certs.curve: brainpool` path is not
  implemented (Go's `crypto/x509` cannot parse Brainpool certificates).
- **No online CRL/OCSP**; expiry is validated, revocation is not.
- **AUTOMATIC TAGS** encoding of a few untagged fields (`SmdpSigned2.ccRequiredFlag`,
  `NotificationMetadata.notificationAddress`) follows the common toolchain
  bindings rather than strict X.680 auto-tagging; this is verified by the golden
  vectors in the `internal/rsp` tests.
