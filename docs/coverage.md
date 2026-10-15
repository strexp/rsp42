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
| ES2+ order-function verifications and status codes | §5.3.1–§5.3.3, Tables 24/27/30 | ✅ (DownloadOrder resend per Table 24 NOTE and the ICCID/Profile-Type codes of Table 24; ConfirmOrder MatchingID uniqueness `8.2.6/3.3`, MatchingID charset (§4.1.1) and the EID rules of Table 27; CancelOrder's mandatory `finalProfileStatusIndicator`, pending-order check, MatchingID/EID association (`8.2.6/3.10`, `8.2.1/3.10`, `8.2.1/3.3`) and the §5.3.3 SM-DS event deletion) |
| ASN.1 binding (`RemoteProfileProvisioningRequest/Response`, `/gsma/rsp2/asn1`) | §6.6 | ✅ (hand-written; ES9+ and ES11) |
| Notification handling (install/enable/disable/delete) | §3.5 | ✅ (euiccSignPIR / euiccNotificationSignature verified; unauthenticated notifications are recorded but not acted on) |
| Certificate chain, role OIDs, EUM nameConstraints/EIN | §4.5.2 | ✅ (expiry checked; CRL out of scope) |
| Multiple CI identities (SGP.26 variants) | §4.5.2 | ✅ (`certs.identities`; selected by `euiccCiPKIdToBeUsed`) |
| SAIP personalization (ICCID/IMSI/K/OPc/PIN/PUK/ADM/SPN/PLMN/MSISDN/ACC/SdKey*/MncLen/EF patches) | §5.5.3 / SAIP | ✅ per-ICCID (DB-backed, K/OPc encrypted at rest); GP key set written to `PE-SecurityDomain`, MNC length to `EF.AD` (6FAD); mandatory-services + GFSTE list recomputed |
| UPP template registry (DB, hot-updatable) | — | ✅ (`upp_templates`; import via `admin upp import`; `profiles.allowed_saip_versions` caps the accepted SAIP baseline) |
| UPP template selection by eUICC profile version | §5.5.3 | ✅ (registry lookup by the eUICC's supported version set — `profileVersion` plus `additionalEuiccProfilePackageVersions`; order override wins; no compatible template fails cleanly with `8.2.6/3.8`) |
| SAIP profile package validation (V2.3.1 constraints) | SAIP Annex A/B, §9 | ✅ (`/upp/validate` + `/upp`: structure/order, mandatory services, AKA/service bits, PE identification, File `doNotCreate`/`fileDescriptor`, GFSTE subset of the 14 Annex B template OIDs, plus the Annex A per-file defaults / §8.3.3 FCP rules / ASN.1 `SIZE` ranges — R1; see `docs/interfaces.md` for the exact boundary) |
| Activation Code Retrieval (ACR) | §4.9 / §5.3.8 | ✅ response metadata (both ACR types) + caller-side Operator confirmation through `ES2+.HandleAcrRequest` (`acr_url`), refusal `8.2.1/1.2` |
| Profile Policy Rules (PPR) | §5.3, §5.7.5 | ✅ populated from `profiles.ppr_ids`; the non-standard ES2+ `downloadOrder.pprIds` body member was removed (C1); a PPR the eUICC lists in `EUICCInfo2.forbiddenProfilePolicyRules` is refused with `8.2.5/4.3` instead of being delivered (§5.7.5 SHALL) |
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

## Open interoperability observations (not yet closed)

These are recorded rather than resolved: the local simulator
(`refs/simulator-testing/INTEROP-TEST-REPORT.md`, lpac × YggdraSIM) passes the
full download, but neither observation has been adjudicated against a real eUICC
or the GSMA conformance tooling.

- **R2 — `ReplaceSessionKeysRequest` (BF26) tagging.** The request encodes its
  members with the generic context tag `04` rather than the AUTOMATIC TAGS
  `80`/`81`/`82` a strict decoder derives; a decoder that enforces the ASN.1
  module could reject it as `scp03tStructureError(7)`. A real-device download
  that fails in the `StoreMetadata`/`ReplaceSessionKeys` phase is the signal to
  revisit the encoder.
- **R3 — ASN.1 binding response nesting.** On the `application/x-gsma-rsp-asn1`
  binding the response carries a single `BF39` layer, whereas strict EXPLICIT
  tagging (as read by `asn1tools` with the GSMA schema) expects two. The JSON
  binding — the only one used by SM-DP+ callers here — is unaffected.
