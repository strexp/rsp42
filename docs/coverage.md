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
| CancelSession | ES9+ §5.6.5 | ◐ (the transactionId is checked and the reason drives the order state; the `euiccCancelSessionSignature` and `smdpOid` verifications of §5.6.5 are the open part — R4 in `docs/esim42-integration-gaps.md`) |
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
| BPP generation (SCP03t / BSP) incl. PPK | §2.5.4 / §5.5 / Annex G | ✅ (verified end to end on a physical SGP.26 test eUICC on 2026-10-15: Released -> Downloaded -> Installed; the earlier segment-group framing defect R5 and the BF26 tagging defect R2 are fixed - `docs/real-card-test-report.md`) |
| Confirmation code (`hashCc`) | §2.2 | ✅ |
| ES2+ order-function verifications and status codes | §5.3.1–§5.3.4, Tables 24/27/30/32 | ✅ (DownloadOrder resend per Table 24 NOTE and the ICCID/Profile-Type codes of Table 24; ConfirmOrder MatchingID uniqueness `8.2.6/3.3`, MatchingID charset (§4.1.1) and the EID rules of Table 27; CancelOrder's mandatory `finalProfileStatusIndicator`, pending-order check, MatchingID/EID association (`8.2.6/3.10`, `8.2.1/3.10`, `8.2.1/3.3`) and the §5.3.3 SM-DS event deletion; ReleaseProfile's Confirmed-order check and `8.2.1/3.5`. Not produced: Table 24's `8.2.5/3.8` Profile-Type/ICCID mismatch row — an already-inventoried ICCID answers `8.2.1/3.3`) |
| ASN.1 binding (`RemoteProfileProvisioningRequest/Response`, `/gsma/rsp2/asn1`) | §6.6 | ✅ (hand-written; ES9+ and ES11. The response nesting deviates — see R3) |
| Notification handling (install/enable/disable/delete) | §3.5 | ✅ (euiccSignPIR / euiccNotificationSignature verified; unauthenticated notifications are recorded but not acted on) |
| Certificate chain, role OIDs, EUM nameConstraints/EIN | §4.5.2 | ✅ (expiry checked; CRL out of scope) |
| Multiple CI identities (SGP.26 variants) | §4.5.2 | ✅ (`certs.identities`; selected by `euiccCiPKIdToBeUsed`) |
| SAIP personalization (ICCID/IMSI/K/OPc/PIN/PUK/ADM/SPN/PLMN/MSISDN/ACC/SdKey*/MncLen/EF patches) | §5.5.3 / SAIP | ✅ per-ICCID (DB-backed, K/OPc encrypted at rest); GP key set written to `PE-SecurityDomain`, MNC length to `EF.AD` (6FAD); mandatory-services + GFSTE list recomputed |
| UPP template registry (DB, hot-updatable) | — | ✅ (`upp_templates`; import via `admin upp import`; `profiles.allowed_saip_versions` caps the accepted SAIP baseline) |
| UPP template selection by eUICC profile version | §5.5.3 | ✅ (registry lookup by the eUICC's supported version set — `profileVersion` plus `additionalEuiccProfilePackageVersions`; order override wins; no compatible template fails cleanly with `8.2.6/3.8`) |
| SAIP profile package validation (V2.3.1 constraints) | SAIP Annex A/B, §9 | ✅ (`/upp/validate` + `/upp`: structure/order, mandatory services, AKA/service bits, PE identification, File `doNotCreate`/`fileDescriptor`, GFSTE subset of the 14 Annex B template OIDs, plus the Annex A per-file defaults / §8.3.3 FCP rules / ASN.1 `SIZE` ranges — R1; see `docs/interfaces.md` for the exact boundary) |
| Activation Code Retrieval (ACR) | §4.9 / §5.3.8 | ✅ response metadata (both ACR types) + caller-side Operator confirmation through `ES2+.HandleAcrRequest` (`acr_url`), refusal `8.2.1/1.2`; both ACR types were verified on a physical eUICC on 2026-10-15, including a full ACR-0 delete-and-redownload cycle (`docs/real-card-test-report.md` §10) |
| Profile Policy Rules (PPR) | §5.3, §5.7.5 | ✅ populated from `profiles.ppr_ids`; the non-standard ES2+ `downloadOrder.pprIds` body member was removed (C1); a PPR the eUICC lists in `EUICCInfo2.forbiddenProfilePolicyRules` is refused with `8.2.5/4.3` instead of being delivered (§5.7.5 SHALL) |
| `otherCertsInChain` | §6.5.2 | ✅ parsed and chained between EUM and CI |
| CRL download / strong CRL checks | §3.5.5 | ✗ (registered risk; interface reserved) |

Legend: ✅ implemented, ◐ partial, ✗ not implemented.

## Notable spec deviations (documented risks)

- **NIST P-256 only**; the Brainpool P256r1 `smdpp.curve`/`smds.curve: brainpool`
  path is not implemented (Go's `crypto/x509` cannot parse Brainpool
  certificates).
- **No online CRL/OCSP**; expiry is validated, revocation is not.
- **AUTOMATIC TAGS** encoding of a few untagged fields (`SmdpSigned2.ccRequiredFlag`,
  `NotificationMetadata.notificationAddress`) follows the common toolchain
  bindings rather than strict X.680 auto-tagging; this is verified by the golden
  vectors in the `internal/rsp` tests.

## Interoperability findings (real-eUICC round, 2026-10-15)

Recorded in full in `docs/real-card-test-report.md`. Two defects were found with
a physical eUICC (SGP.26 Variant O test card, `lpac` as the LPA) and fixed; one
observation remains open.

- **R5 — BPP segment-group framing (fixed).** `internal/rsp/bpp.go` wrapped every
  `A0`/`A1`/`A2`/`A3` member in an extra `[7]`/`[8]`/`[6] OCTET STRING, so the
  wire form was `87 1A 87 18 ...` instead of `87 18 ...`. SGP.22 Annex H types
  the member AS the '87'/'88'/'86' TLV (Table 4 gives its content directly), and
  a physical eUICC rejected the doubly wrapped form with `configure_isdp` /
  `scp03tSecurityError(8)` while accepting `osmo-smdpp`'s single-wrapped package.
  `segmentGroupBytes`/`groupSegments` now emit and read the segment TLV verbatim;
  the golden vectors and the pySim-derived `testdata/vectors/bpp_decode.json`
  were updated. The simulator round had missed it because YggdraSIM was patched
  to accept both forms and `testdata/vectors/rsp_golden.json` encoded the wrong
  bytes.
- **R2 — `ReplaceSessionKeysRequest` (BF26) tagging (fixed).** The members used
  the generic context tag `04`; `RSPDefinitions` is an AUTOMATIC TAGS module, so
  they are `80`/`81`/`82`. The physical card processes the `80`/`81`/`82` form
  (verified both via the `osmo-smdpp` package it installed and via rsp42's own
  post-fix install), and the encoder now emits it.
- **R3 — ASN.1 binding response nesting (open).** On the
  `application/x-gsma-rsp-asn1` binding every response function carries a single
  function layer (one `BF39`, `BF3B`, `BF3A`, `BF41` or `BF40`), whereas the
  extra explicit layer that `AUTOMATIC TAGS` derives for a tagged CHOICE (as read
  by `asn1tools` with the GSMA schema) expects two. Reproduced live
  (`A2 { BF39 { A0 ... } }` on 2026-10-15); the request direction is unaffected,
  and so is the JSON binding - the only one used by SM-DP+ callers here. `lpac`
  does not use the ASN.1 binding, so a §6.6 LPA is still needed to adjudicate.
