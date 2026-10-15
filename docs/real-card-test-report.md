# Real-eUICC test report (2026-10-15)

Scope: run the rsp42 SM-DP+/SM-DS against a **physical eUICC** (ACR1581 contact
reader, driven by `lpac` as the LPA), exercise the live ES2+/ES9+/ES11/ES12 and
management interfaces, settle the open interoperability questions recorded in
`docs/coverage.md` / `TODO.md`, and fix what the physical device proved wrong.

Outcome: **the full lifecycle Released -> Downloaded -> Installed now completes
on the real eUICC**, after two code fixes (both reproduced as failures on the
card before the fix and verified on it afterwards):

* `internal/rsp/bpp.go` — the BPP segment groups wrapped every SCP03t data block
  in an extra `[7]`/`[8]`/`[6]` OCTET STRING layer (finding F1/R5);
* `internal/rsp/download.go` — `ReplaceSessionKeysRequest` (BF26) tagged its
  members `04` instead of the AUTOMATIC TAGS `80`/`81`/`82` (finding F2/R2).

## 0. Findings at a glance

| # | Finding | Status |
|---|---|---|
| F1 / R5 | BPP segment groups were wrapped one OCTET STRING layer too deep; the card rejected every download at `configure_isdp` / `scp03tSecurityError(8)`. | **fixed, verified on the card** (§3, §4, §5) |
| F2 / R2 | BF26 members used the generic tag `04` instead of `80`/`81`/`82`. | **fixed, verified on the card** (§4, §5) |
| F3 / R3 | ES9+ ASN.1 binding responses carry a single function layer (`A2 { BF39 { A0 ... } }`) rather than the two an AUTOMATIC TAGS CHOICE derives. | open observation; needs a §6.6 LPA to adjudicate (§6) |
| F4 | `smdpp.es12.smds_address` cannot carry a port: the ES12 client hardcodes `:9444`. | operational note (§6, `docs/operations.md`) |
| F5 | `/usr/bin/lpac` 2.3.0 (distro build) segfaults when `LPAC_APDU_PCSC_DRV_IFID` is set without `LPAC_APDU_PCSC_DRV_NAME`; the source-tree build `refs/lpac/build/src/lpac` is fine. | tooling: use the source-tree build (§1) |
| F6 | The ACR1581 card-presence signal flaps (`SCARD_E_NO_SMARTCARD`) and the card drops after a few tens of seconds idle. | tooling: run card work in one continuous pass (§1) |
| F7 | The earlier simulator round masked F1: YggdraSIM was patched to accept both wrapping forms and the golden vectors encoded the double-wrapped form. | test-coverage lesson (§3.4) |
| F8 | `POST /upp/validate` answers `200 {"error": ..., "valid": false}` on a parse failure, but the OpenAPI `UPPValidation` schema declared neither `error` nor an optional-`inspection` branch. | **fixed**: the schema declares the optional `error` and requires only `valid`; `TestResourceResponsesMatchTheDeclaredSchema` drives both 200 shapes (§7) |

## 1. Environment

| Component | Version / path | Notes |
|---|---|---|
| eUICC | EID `89049032123451234512345678901235`, ATR `3B 9F 96 80 3F C7 83 80 31 E0 73 F6 21 13 67 56 07 62 E0 27 03 02 86` | profileVersion 2.3.1, svn 2.5.0, fw 39.3.2, GP 2.3.0, SAS `VD-MD-UP-1026`, CI PK ID `f54172bd...` (SGP.26 v3.0.2 Variant O) |
| Reader | ACS ACR1581 1S Dual Reader | ICC slot = PC/SC reader index **1** (`LPAC_APDU_PCSC_DRV_IFID=1`); index 0 is the contactless slot |
| LPA | `refs/lpac/build/src/lpac` (`2.3.0.r463.82ada9e53251`) | **use this build, not `/usr/bin/lpac`** (F5); curl HTTP driver, peer verification disabled upstream |
| SM-DP+ / SM-DS | `bin/rsp42 smdpp` / `smds` from this tree | isolated test instance, ports 18443/18444/19000 and 19443/19444/19100, SGP.26 Variant O certs, 18 TS.48 templates seeded |
| Cross-check SM-DP+ | `refs/pysim/osmo-smdpp.py` (HEAD `9aa8934`) | independent upstream reference; used to decide whether a failure was rsp42's or the card's |
| Capture | `refs/simulator-testing/e2e-run/capture_proxy.py` | TLS-terminating proxy in front of either SM-DP+ |

Operational notes:

* Card commands must be issued as one continuous pass; after a few tens of
  seconds without activity the reader loses the card (`SCardConnect` ->
  `0x8010000C`). A re-insertion restores it.
* With the source-tree LPA, `LPAC_APDU_PCSC_DRV_IFID=1` alone selects the ICC
  slot; the distro build additionally needs `LPAC_APDU_PCSC_DRV_NAME` because it
  dereferences a NULL reader name when only the IFID is set.

## 2. Baseline (no card)

`make build`, `go vet ./...`, `golangci-lint run` — clean (0 issues).
`go test ./...` — every package passes.

## 3. The real-card failure and its root cause (F1/R5)

Before the fix the download completed the ES9+ handshake (the eUICC verified
`serverSignature1`/`smdpSignature2`, rsp42 produced the BPP, the Profile moved
`Released -> Downloaded`) and then failed in the first protected block:

```
bppCommandId = configure_isdp (1)     errorReason = scp03t_security_error (8)
```

`internal/rsp/bpp.go::segmentGroupBytes` appended each segment - which already
carried its own `87`/`88`/`86` tag and length - as the *content* of a further
`[7]`/`[8]`/`[6] OCTET STRING, producing a doubly wrapped member:

| group | rsp42 (rejected) | osmo-smdpp (accepted) |
|---|---|---|
| `A0` firstSequenceOf87 | `A0 1C 87 1A 87 18 <cipher> <mac>` | `A0 1A 87 18 <cipher> <mac>` |
| `A1` sequenceOf88 | `A1 ... 88 81A5 88 81A2 <plain> <mac>` | `A1 ... 88 8194 <plain> <mac>` |
| `A2` secondSequenceOf87 | `A2 ... 87 4A 87 48 <cipher> <mac>` | `A2 ... 87 48 <cipher> <mac>` |
| `A3` sequenceOf86 | `86 <outer> 86 <inner> ...` | `86 <len> ...` |

### 3.1 Why this is wrong (spec)

* SGP.22 Annex H types the groups as
  `firstSequenceOf87 [0] SEQUENCE OF [7] OCTET STRING, -- sequence of '87' TLVs`:
  the group member *is* the SCP03t data block TLV. The member tags
  `[6]/[7]/[8]` = `0x86/0x87/0x88` are exactly the SGP.02 SCP03t data-block tags,
  and §2.5.3 says "Each data segment of the PPP is identified by the tag '86' as
  defined in SGP.02 [2]".
* SGP.22 Table 4 gives the semantics: the `'87'` TLV's content is the
  `ES8+.ConfigureISDP` TLV (`'88'` = StoreMetadata MAC-only, `'86'` = PPP with
  the PPK). There is no room for an intermediate OCTET STRING.
* §2.5.5 segments the SBPP as "Tag and length fields of the first sequenceOf87
  TLV plus the first '87' TLV", i.e. `'87'`/`'86'` are direct children of
  `A0`/`A2`/`A3`.

### 3.2 Why the project got it wrong

* The crypto layer (`internal/crypto/bsp.go`) returns a *complete* SCP03t TLV;
  the codec layer treated that value as the OCTET STRING *content* and prefixed
  the tag again. The two live in different packages and the value-vs-TLV
  boundary is where the extra layer slipped in. It has been there since the
  initial commit, with no rationale recorded.
* The unit test locked it in: `TestAssembleBoundProfilePackage` passes
  `FirstSequenceOf87: {"8704aabbccdd"}` (already a complete `'87'` TLV) and the
  golden expected `a0 08 87 06 87 04 aabbccdd`; the decoder was written as the
  matching inverse, so the round-trip was green.
* The pySim reference vector (`testdata/vectors/bpp_decode.json`) is
  double-wrapped because it was built to satisfy a schema-driven *decoder*:
  decoding osmo-smdpp's single-wrapped BPP with `asn1tools` yields the OCTET
  STRING content (`cipher||MAC`, no tag) and feeding that to pySim's own
  `BspInstance.demac_and_decrypt` fails with a MAC mismatch, while the
  double-wrapped fixture works. rsp42 adopted the fixture as evidence.
* YggdraSIM had been patched locally to accept both forms
  (`SIMCARD/sgp.py::_unwrap_bsp_member`), removing the last automated check.

### 3.3 How it was proven

The same card, the same `lpac` and the same UPP: osmo-smdpp's single-wrapped BPP
installs, rsp42's double-wrapped one is rejected at `configure_isdp`. Deriving
the session keys independently (X9.63/SHA-256 over osmo-smdpp's logged
`shared_secret`, `hostId = b'mahlzeit'`, EID as BCD) reproduces osmo's `A0` MAC
byte-for-byte over the ciphertext, so the card MACs the ciphertext
(encrypt-then-MAC) and the only difference left in the failing block is the
framing: the eUICC reads the outer `87 1A` as the segment, leaving an 18-byte
"ciphertext" and a MAC it can never match.

## 4. Fixes applied

`internal/rsp/bpp.go`

* `segmentGroupBytes` appends the segment TLVs verbatim (the `[7]`/`[8]`/`[6]`
  OCTET STRING tag *is* the SGP.02 data-block tag) instead of re-wrapping them.
* `groupSegments` collects each child's `Raw` (the complete TLV) rather than its
  `Value`, so the decoder hands `crypto.DemacAndDecrypt/DemacOnly` what they
  expect.
* The `BoundProfilePackage` field comments now say the slices hold complete
  `'87'`/`'88'`/`'86'` TLVs.

`internal/rsp/download.go`

* `ReplaceSessionKeysRequest.Encode` tags the three members `80`/`81`/`82`
  (`asn1.Prim(asn1.Ctx(n, false), ...)`) instead of `asn1.Octet` (`04`).

Vectors and tests

* `testdata/vectors/rsp_golden.json`: the `BoundProfilePackage` and
  `GetBoundProfilePackageResponse_Ok` entries now carry the single-wrapped bytes
  (`a0 06 87 04 aabbccdd ...`) with recomputed lengths; a
  `ReplaceSessionKeysRequest` entry was added.
* `internal/rsp/rsp_test.go`: new `TestEncodeReplaceSessionKeysRequest` pins the
  `80/81/82` tagging.
* `testdata/vectors/bpp_decode.json`: the pySim-derived reference BPP was
  normalised to the wire form (one OCTET STRING level removed, `note` field
  added) and `internal/crypto/bpp_vector_test.go::childSegments` now reads
  `k.Raw`, so the crypto test exercises the real framing.

## 5. Post-fix verification on the physical eUICC

Continuous run (single pass), LPA = `refs/lpac/build/src/lpac`:

```
$ rsp42 admin es2p …  (ES2+ downloadOrder + confirmOrder, matchingId MATCH-E2E-FIX2)
$ LPAC_APDU_PCSC_DRV_IFID=1 ./refs/lpac/build/src/lpac profile download \
      -s testsmdpplus1.example.com -m MATCH-E2E-FIX2
  es10b_prepare_download -> es9p_get_bound_profile_package ->
  es10b_load_bound_profile_package -> success
  data: {"seqNumber":8,"iccid":"89000123450000000094","bppCommandId":"unknown"}
$ ./refs/lpac/build/src/lpac profile list
  {"iccid":"89000123450000000094","isdpAid":"a0000005591010ffffffff8900001200",
   "profileState":"disabled","profileClass":"operational"}      <- installed on the card
$ ./refs/lpac/build/src/lpac notification process -a -r
  es10b_retrieve_notifications_list 8 -> es9p_handle_notification 8 -> success
$ GET /admin/api/v1/profiles/89000123450000000094
  {"state":"Installed","downloadAttempts":1,"installedAt":"2026-10-15T12:32:02Z"}
```

Outbound ES2+ notifications delivered to the operator stub:

* `notificationPointId 3` (download) `Executed-Success` for ICCID `...094`;
* `notificationPointId 4` (installation) `Executed-Success` for ICCID `...094`.

This also confirms F2 on hardware: the card processed the `A2`/BF26 group with
the new `80/81/82` tagging as part of the same accepted package.

**ACR-1 (`HandleAcrRequest`)** — `lpac profile download -m ACR-1-89000123450000000094`
(the profile is `Installed`) produced:

* an outbound `ES2+.HandleAcrRequest` to the configured Operator stub with body
  `{"header":{"functionRequesterIdentifier":"2.999.10",...},"iccid":"89000123450000000094"}`;
* `rsp42_acr_requests_total{outcome="allowed"} 1` and an audit row
  (`interface=es2p`, `function=handleAcrRequest`, `outcome=allowed`);
* outbound `notificationPointId 17` (activation code retrieval)
  `Executed-Success`;
* the LPA then cancelled the session (`8.2.6`-class "unknown"): expected for an
  ACR-1 availability check, which returns AC metadata rather than a BPP.

Earlier failed attempts (same card) are still recorded in the rsp42 inventory:
5/1 verifiable failed-install notifications moved the pre-fix profiles to
`Error`, and the two unverifiable osmo-smdpp notifications were recorded without
a state change.

## 6. Live interface sweep

**ES2+ (mTLS, JSON)** — all documented codes reproduced:

| Probe | Result |
|---|---|
| `downloadOrder` malformed ICCID / unknown template / foreign tenant | `8.1/1.2` / `8.2.5/3.9` / `8.2.5/1.2` |
| `confirmOrder` missing `iccid` / missing `releaseFlag` | `8.1.1/2.2` |
| `confirmOrder` bad `matchingId` charset / duplicate `matchingId` / `eid` mismatch | `8.1/1.2` / `8.2.6/3.3` / `8.1.1/3.10` |
| `cancelOrder` wrong `matchingId` / wrong `eid` / bad final status / already downloaded | `8.2.6/3.10` / `8.2.1/3.10` / `8.1/1.2` / `8.2.1/3.3` |
| `releaseProfile` unknown ICCID | `8.2.1/3.9` |
| `handleDownloadProgressInfo` (ES2+ inbound) | HTTP 204 |
| `confirmOrder(smdsAddress=...)` | registers an ES12 event (below) |

**Management API** — `GET /openapi.json`; `/profiles` (filter/sort/page),
`/profiles/stats?groupBy=state`, `/audit` page + `afterId` cursor (N1),
`/callbacks` (N2), tenant delete protection 409 -> `?force=true&reassignTo=` 204
(N3), SM-DS `/events` write API (N8), `/metrics`.

**UPP registry** — `/upp` list (18 templates); `POST /upp/validate` on
TS48v2.SAIP2.3.BERTLV: `valid:true`, 29 warnings; a truncated or garbage input
answers `valid:false` with a top-level `error` (F8, see §7); `/upp/{name}/schema`
(N4); `/upp/render` with ad-hoc base64 data (N5, `rendered:true`,
`template.name == "<ad-hoc>"`); `/upp/{name}/bytes` is byte-identical to the
source file; `/decoded` (30 elements, 201 files); `deactivate`/`activate`;
`clone` into a tenant; re-upload archives a revision (`/versions` total 1) and
`/versions/{id}/restore` restores the previous sha256.

**N16 (SAIP version cap)** — a template patched to SAIP 3.3 is refused by
`POST /upp` with `409 saip_version_not_supported`
(`{"details":{"maxSupported":"2.3","templateVersion":"3.3"}}`); a SAIP 2.1
template is accepted (below the baseline); `/upp/validate` still reports the
version it read (`3.3`) so an unstored template can be inspected.

**ES12 (SM-DP+ -> SM-DS)** — `confirmOrder` with `smdsAddress` reaches the SM-DS
`registerEvent` (event visible via the SM-DS admin `/events` with the right
eventId/iccid/rspServerAddress) and is recorded locally in
`smds_registrations`; direct `registerEvent`/`deleteEvent` (mTLS) both answer
`Executed-Success`. Note F4: `smdpp.es12.smds_address` cannot express a port
(the client hardcodes `:9444`), so the test SM-DS had to sit on 9444.

**ASN.1 binding (R3)** — `POST /gsma/rsp2/asn1` with
`Content-Type: application/x-gsma-rsp-asn1` and a real `euiccInfo1` answers 200
in the same content type; the response body is `A2 { BF39 { A0 ... } }`, i.e. a
single function layer, reproducing R3. `lpac` only uses the JSON binding, so a
§6.6 LPA is still needed to adjudicate.

**Metrics** — the SM-DP+ admin exposes the documented families
(`rsp42_downloads_total`, `rsp42_acr_requests_total`,
`rsp42_euicc_v3_capable_total`, `rsp42_profile_version_not_supported_total`,
`rsp42_es2p_profile_type_unparsed_total`, `rsp42_es2p_tenant_unmapped_total`,
`rsp42_es12_register_failures_total`, `rsp42_es2p_callback_queue`,
`rsp42_iccid_pool`, `rsp42_session_gc_total`,
`rsp42_iccid_reservation_gc_total`) and the SM-DS admin the two event families
(`rsp42_smds_events`, `rsp42_smds_event_gc_total`).

## 7. TODO.md item status after this round

| TODO.md item | Status |
|---|---|
| §2-1 SAIP template OID table + constraint validation, §2-2 per-file defaults | exercised live (`/upp/validate`: valid template -> `valid:true` + 29 warnings; malformed input -> `valid:false`); pinned by the `internal/saip` tests |
| §2-3 `SdKey*` / `MncLen` personalization | covered by `internal/service` (`TestLoadUPPAppliesPersonalization`, `TestBuildStoreMetadataPPR`); the real card exercised personalization end to end via the successful install |
| §2-4 ES9+ `CancelSession` signature verification | still partial by design; the live `cancelSession` (transactionId-only check) was exercised on every failed attempt and after the ACR-1 session |
| §2-5 Brainpool, §2-6 BER indefinite length, §2-7 V3.x PE tags | untouched (card is NIST, no sample triggers) |
| §2-8 BPP group framing (new) | **fixed + verified on the card** (§4, §5) |
| §2-9 BF26 tagging (R2, new) | **fixed + verified on the card** (§4, §5) |
| §2bis N1/N2/N3/N4/N5/N7/N8/N13/N16 | verified live (see §6); N16 with a patched SAIP 3.3 template |
| §2bis N9 (latency histogram), N6/N10, N14 | unchanged (deferred / out of scope) |
| §3-1 `bertlv` containment | `TestBertlvIsContained` passes (the allowlist is `internal/asn1/construct.go` + `tools.go`) |
| §3-2 `errgroup` in `serveAll`, §3-3 panic contract, §3-4 byte helpers, §3-5 DIP tests | re-verified by inspection + `go test` |
| §4-1 pySim `contrib/es2p_client.py` field comparison | not done; the live ES2+ probes cover the field-level contract from the wire side instead |
| §4-2 lpac manual E2E + real card | **done**: full install on the physical eUICC (§5) |
| §4-3 bertlv multi-byte length, §4-4 cascade partition/timeout, §4-5 certificate rotation | unchanged (non-blocking) |
| F8 (new) | `POST /upp/validate` parse failures answer `{"error": ..., "valid": false}` while the OpenAPI `UPPValidation` schema declared neither `error` nor an optional-`inspection` branch; a generated client would be surprised. **Fixed**: the schema now declares the optional `error` member (with a description of the two 200 shapes) and requires only `valid`, and `TestResourceResponsesMatchTheDeclaredSchema` drives both shapes. |

## 8. Evidence artifacts

Untracked, under `.e2e-tmp/` (this environment only):

* `e2e/config.yaml` — isolated test configuration (ports, operator callback stub).
* `e2e/logs/smdpp.log`, `smds.log`, `callback_sink.log`, `callbacks.jsonl`.
* `e2e/logs/capture.jsonl` + `e2e/bpp.bin` — the pre-fix failing rsp42 BPP.
* `osmo/capture.jsonl`, `osmo/osmo-bpp.bin`, `osmo/osmo.log` — the osmo-smdpp
  cross-check (shared secret, host id, accepted BPP).
* `e2e/logs/lpac-MATCH-E2E-FIX2.out` — the successful download/install trace;
  `e2e/logs/lpac-acr1b.out` — the ACR-1 trace.
* `e2e/bsp_check.py`, `e2e/verify_session_bpp.py` — independent BSP/KDF checkers.
* `e2e/es2p-probes*.sh`, `e2e/run-download.sh` — the live probes.

## 9. Card state after the round

The eUICC carries two test profiles:

* `89000123456789012341` (`OsmocomSPN` / `TS48V2`, disabled) - installed from
  `osmo-smdpp` during the cross-check;
* `89000123450000000094` (`RSP42` / `TS48v2_SAIP2.3_BERTLV.der`, disabled) -
  installed from the fixed rsp42 and reported as `Installed` by the SM-DP+.

Both should be deleted (`profile delete`) before the card is used for anything
else. The card's notification queue is empty.
