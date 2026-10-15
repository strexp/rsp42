# Interfaces

The LPA-facing interfaces (ES9+, ES11) support both SGP.22 bindings, selected per
request via `Content-Type`:

- **JSON binding** (`application/json`, §6.5): per-function paths, binary fields
  are base64-encoded ASN.1 structures, `transactionId` is an uppercase hex
  string. Synchronous functions return HTTP 200 with a
  `header.functionExecutionStatus`; notification functions return HTTP 204.
- **ASN.1 binding** (`application/x-gsma-rsp-asn1`, §6.6): a single generic path
  `POST /gsma/rsp2/asn1` carrying a DER-encoded
  `RemoteProfileProvisioningRequest`/`Response` (an explicit `A2` envelope around
  the function TLV). HandleNotification returns HTTP 204.

Both are served on the same ES9+/ES11 listeners. The ES2+/ES12/ES15 interfaces
use the JSON binding only (as the specification mandates).

## ES9+ (SM-DP+, LPA-facing)

| Function | Path |
|---|---|
| InitiateAuthentication | `POST /gsma/rsp2/es9plus/initiateAuthentication` |
| AuthenticateClient | `POST /gsma/rsp2/es9plus/authenticateClient` |
| GetBoundProfilePackage | `POST /gsma/rsp2/es9plus/getBoundProfilePackage` |
| HandleNotification | `POST /gsma/rsp2/es9plus/handleNotification` (204) |
| CancelSession | `POST /gsma/rsp2/es9plus/cancelSession` |

`initiateAuthentication` request: `{euiccChallenge, euiccInfo1, smdpAddress}`.
`authenticateClient` request: `{transactionId, authenticateServerResponse}`, plus
the optional `useMatchingIdForAcr` boolean of §6.5.2.8. The member is accepted
but ignored: ACR is detected from the ACR-shaped MatchingID
(`ACR-<0|1>-<ICCID>`, §4.9.1) carried in `ctxParams1`, not from the flag.
`getBoundProfilePackage` request: `{transactionId, prepareDownloadResponse}`.

## ES2+ (SM-DP+, Operator-facing, mTLS)

`POST /gsma/rsp2/es2plus/{downloadOrder,confirmOrder,cancelOrder,releaseProfile,
handleDownloadProgressInfo,handleAcrRequest}`. Requests carry
`header{functionRequesterIdentifier, functionCallIdentifier}`.

### Tenant attribution

The caller's `header.functionRequesterIdentifier` is mapped to a tenant by
`smdpp.es2p.requester_tenants` (SGP.22 §6.5.1.3 imposes no format on the field).
An unmapped requester falls back to the platform-default tenant (`""`); the
fallback is recorded on the audit row as `detail.warning=unmapped` together with
`detail.requester`, and counted in `rsp42_es2p_tenant_unmapped_total`, so an
operator health check can alert on a carrier that was never registered. With an
empty `requester_tenants` table nothing is flagged: a single-tenant deployment
has nothing to map. A tenant may only operate on its own ICCIDs: a foreign ICCID
answers `8.2.1/1.2` on the order functions that address an existing Profile
(`confirmOrder`, `cancelOrder`, `releaseProfile`), while `downloadOrder` answers
`8.2.1/3.3` (the ICCID cannot be issued); using another tenant's Profile
Type/template answers `8.2.5/1.2`.

### Profile/template selection

`downloadOrder.profileType` is "content free information defined by the
Operator" (§6.5.2.1). rsp42 interprets `"<tenant>/<template>"` as a template
selector; any other value stays opaque and template resolution falls back to the
eUICC's advertised SAIP version, then the tenant default, then
`profiles.default_upp`. An opaque value is not silent: it increments
`rsp42_es2p_profile_type_unparsed_total` and is audited with
`warning=profileType-unparsed` (C2).

The tenant part must be the caller's own tenant, except that an **empty tenant
part** (`"/<template>"`) selects a template owned by the platform-default tenant
— i.e. a global template, including one promoted with `POST /upp/{name}/promote`.
That form is the only way to name such a template, because no non-empty prefix
denotes the platform-default owner; the name is still resolved with the caller's
scope, so a tenant only reaches its own template or a global one. A selector with
no template name (`"/"`) is malformed (`8.2.5/3.9`), and another tenant's template
is an authorisation failure (`8.2.5/1.2`). At download time the resolution order
is: template pinned on the order, session template (eUICC version), tenant
default, global default; a pinned template is authoritative and there is no "any
template" fallback.

The `downloadOrder` body is the closed Table 22 set: `eid`, `iccid`,
`profileType`. There is no private body extension (the former `pprIds` member
was removed, C1); Profile Policy Rules travel through `profiles.ppr_ids` on the
management API.

The `downloadOrder` response carries **only `iccid`** (Table 23: the only
additional output data). `smdpAddress` is not a DownloadOrder output — it is an
optional output of `confirmOrder` (Table 26), used when a specific order must be
downloaded from a different SM-DP+ address.

A failed allocation is reported with a specific code: no Profile of the
requested type is available (pool/quota exhausted) is `8.2.5/3.7`, an unusable
ICCID (already in use, blocked) is `8.2.1/3.3`, and any other allocation
failure is `8.2/4.2` (C3).

### Resend semantics

Per Table 24 NOTE, a repeated `downloadOrder` naming an ICCID that already
exists in `Allocated`/`Linked` with the same tenant, `profileType` and EID
answers `Executed-Success` with that ICCID and performs no further action, so an
operator retry after a lost response is safe. The comparison is on the supplied
values only: an omitted `profileType`/`eid` matches any stored one.

### ConfirmOrder verifications

- A supplied `matchingId` must consist only of upper case alphanumeric
  characters and `-` (§4.1.1); anything else answers `8.1/1.2`. An empty value
  means "generate one".
- A `matchingId` that another order already uses answers **`8.2.6/3.3`** (Table
  27, Matching ID — Already in Use (Uniqueness)). The unique index decides, so
  concurrent confirms cannot both win, and the store error itself is never
  returned to the caller.
- An `smdsAddress` makes the EID mandatory — the SM-DS event is keyed by it — so
  an order with no EID answers `8.1.1/2.2` (Table 27).
- A `confirmOrder.eid` that disagrees with the order answers `8.1.1/3.10` (Table
  27; see also the idempotency note below).

### CancelOrder verifications

`finalProfileStatusIndicator` is **mandatory** (Table 28) and has exactly two
values, `Available` (return the ICCID to inventory) and `Unavailable` (keep it
out of inventory). An absent element answers `8.1.1/2.2`; an unrecognised value
answers `8.1/1.2` (malformed request — this is not an authorisation failure).

A `cancelOrder` is a cancellation of a *pending* order, so the SM-DP+ verifies
(§5.3.3) and, per Table 30, answers:

| Condition | Code |
|---|---|
| ICCID unknown | `8.2.1/3.9` |
| ICCID not allowed for the caller | `8.2.1/1.2` |
| Profile already downloaded (`Downloaded`/`Installed`) | `8.2.1/3.3` |
| supplied `eid` is not the associated one | `8.2.1/3.10` |
| supplied `matchingId` is not the associated one | `8.2.6/3.10` |

On success the order is cancelled and, per §5.3.3, the SM-DS event registration
of the order is deleted. A deletion failure does not fail the cancel (the order
is already cancelled); it is logged and counted in
`rsp42_es12_register_failures_total`.

### Idempotency

`confirmOrder`, `cancelOrder` and `releaseProfile` (and the equivalent Admin API
writes) accept an `Idempotency-Key` HTTP header — SGP.22 §6.2 explicitly allows
additional header fields, so no request-body member is added. The same key with
the same body replays the recorded response and repeats no side effect
(`Idempotency-Replayed: true`); the same key with a different body answers HTTP
409 `idempotency_key_reused`; a 5xx response releases the key for retry.

### Activation Code Retrieval confirmation (SM-DP+ -> Operator)

When the SM-DP+ receives an Activation Code Retrieval request (`matchingId`
`ACR-<0|1>-<ICCID>`, §3.1.7/§3.1.8), it SHALL confirm it with the Operator
before issuing anything, for **both** ACR types — the availability check
(`ACR-1-…`) and the activation code redownload (`ACR-0-…`).

| | |
|---|---|
| Function | `ES2+.HandleAcrRequest` (§5.3.8) |
| Endpoint | `notifications.es2p_callback.acr_url` |
| Request body | `{header, iccid}` — `iccid` is the function's only additional input data (§5.3.8 Table 32d / §6.5.2.20); no private members are added |
| Operator answer | `Executed-Success`/`Executed-WithWarning` = confirmed; `Failed` (typically `8.2.1/1.2`, Table 32e) = refused |
| On refusal | the ES9+ answer is `8.2.1/1.2` ("Operator refused Activation Code Retrieval"); the profile keeps its matching id |
| Retries | transport/HTTP failures are retried with backoff; a refusal is a business decision and is never retried |
| Time bound | `notifications.es2p_callback.acr_timeout` (default `10s`) bounds the whole confirmation, retries included, so an unreachable Operator cannot stall `authenticateClient` |

This configuration is independent of the progress callbacks: setting `acr_url`
enables ACR confirmation even when `enabled`/`url` are empty, and enabling the
progress callbacks never requires an ACR URL. Every call is counted
(`rsp42_acr_requests_total{tenant,outcome}`) and audited
(`interface=es2p`, `function=handleAcrRequest`).

An `ACR-0-…` redownload rotates the Profile's MatchingID and returns the new
Activation Code in `activationCodeForProfileRedownload` (SSD); the new
MatchingID is a plain `MATCH-…` token, never an `ACR-…` one, so it cannot be
mistaken for another retrieval request (§4.9.1). SGP.22 §3.1.7 makes the code
usable only once the associated Delete Notification has been received: set
`profiles.allow_redownload_after_delete: true` to return the Profile to
`Released` on a **verified** delete notification. With the default (`false`)
`Installed` stays terminal and an ACR-0 code can never be used — startup logs a
warning when `acr_url` is set and the opt-in is missing.

### Download progress notifications (SM-DP+ -> Operator)

`handleDownloadProgressInfo` payload:
`{header, eid, iccid, profileType, timestamp, notificationPointId,
notificationPointStatus, resultData, tenantId, externalRef, matchingId}`.
`tenantId`, `externalRef` and `matchingId` are rsp42 additions (this function is
SM-DP+ -> Operator, so it is not bound by the ES2+ input schema). Delivery is
persisted first and retried with backoff before being dead-lettered.

`notificationPointId` values (§5.3.5):

| id | meaning |
|---|---|
| 1 | eligibility/authorisation check failure — including `8.2.5/4.3` when the Profile would carry a PPR the eUICC lists in `EUICCInfo2.forbiddenProfilePolicyRules` (§5.7.5) |
| 2 | confirmation code failure |
| 3 | download result |
| 4 | installation result |
| 17 | activation code retrieval |

Notifications are recorded with their signature outcome either way. A **verified**
`delete` notification additionally returns the Profile to `Released` when
`profiles.allow_redownload_after_delete` is set (SGP.22 §3.1.7); with the default
`false` a delete notification is recorded but changes no state.

## ES11 (SM-DS, LPA-facing)

Reuses the ES9+ path semantics on the SM-DS FQDN
(`initiateAuthentication`, `authenticateClient`). `authenticateClient` responds
with `{transactionId, eventEntries:[{eventId, rspServerAddress}]}`.

## ES12 / ES15 (SM-DS, SM-DP+/SM-DS-facing, mTLS)

| Function | Path |
|---|---|
| RegisterEvent | `POST /gsma/rsp2/es12/registerEvent` |
| DeleteEvent | `POST /gsma/rsp2/es12/deleteEvent` |

The caller is identified by the registered-ID SAN of its mTLS client
certificate (falling back to `functionRequesterIdentifier`). ES15 is the same
function invoked by an Alternative SM-DS.

The SM-DP+ carries correlation metadata out of band as extra headers (allowed by
§6.2), so the closed ES12 body is not extended:

| Header | Meaning |
|---|---|
| `X-RSP42-Tenant` | tenant the event belongs to |
| `X-RSP42-ICCID` | ICCID correlated with the event, when known |
| `X-RSP42-Matching-Id` | matchingId correlated with the event, when known |

An SM-DS may also map a caller OID to a tenant via
`smds.es12.requester_tenants` when no header is present.

## Status codes

Failures use `header.functionExecutionStatus.status = "Failed"` with
`statusCodeData{subjectCode, reasonCode, message}` (SGP.22 §5.2.6), e.g.
`8.8.1/3.8` invalid SM-DP+ address, `8.8.2/3.1` unsupported CI key,
`8.10.1/3.9` unknown transaction, `8.2.7/6.4` confirmation code invalid,
`8.9.5/3.3` EventID in use, `8.9.5/3.9` event not found.

ES2+ distinguishes the frequently confused conditions so the operator can
branch correctly:

| Condition | Code |
|---|---|
| ICCID unknown to the SM-DP+ | `8.2.1/3.9` |
| Profile Type / template unknown | `8.2.5/3.9` |
| Profile Type / template (or ICCID) not allowed for the caller | `8.2.5/1.2` / `8.2.1/1.2` |
| Mandatory request element missing (e.g. `iccid`, `finalProfileStatusIndicator`) | `8.1.1/2.2` |
| Malformed request value (bad ICCID, bad `finalProfileStatusIndicator`, bad `matchingId` charset) | `8.1/1.2` |
| `confirmOrder.eid` disagrees with the download order | `8.1.1/3.10` |
| `confirmOrder` `matchingId` already used by another order | `8.2.6/3.3` |
| `cancelOrder.matchingId` is not the associated one | `8.2.6/3.10` |
| `cancelOrder.eid` is not the associated one | `8.2.1/3.10` |
| `cancelOrder` on an already downloaded Profile | `8.2.1/3.3` |
| No Profile of the requested type is available (quota/pool exhausted) | `8.2.5/3.7` |
| The requested ICCID cannot be issued (in use / blocked) | `8.2.1/3.3` |
| No template compatible with the eUICC's SAIP versions (N12) | `8.2.6/3.8` + readable message |

`8.2.6/3.8` is Table 43's "MatchingID (AC_Token or EventID) is refused": it is
used by `CodeProfileNotEligible` when the MatchingID cannot be resolved (empty
or unknown). It is not the "no eligible Profile" row — Table 43 gives that as
`8.2.5/4.3` ("No eligible Profile for this eUICC/Device"), used by
`CodeNoEligibleProfile` when the Profile would carry a PPR the eUICC forbids.

The SAIP-version case (`CodeProfileVersionNotSupported`, N12) has no
subject/reason row of its own in SGP.22, so reusing `8.2.6/3.8` is a deliberate
non-spec choice rather than a spec overload. Callers must branch on the
`message` to tell it from the MatchingID-refused case. To keep the two
machine-distinguishable, the version case always uses a stable message prefix
(`no UPP template compatible with the eUICC's SAIP versions …`, or the
no-version-at-all variant `eUICC advertised no usable SAIP profile version …`)
and records `euiccProfileVersion`, `supportedVersions` and
`lowestTemplateVersion` in the download timeline/audit; the eligibility case
does not.

**Template / eUICC version compatibility (N11/N12).** The eUICC advertises its
SAIP versions in EuiccInfo2 (`profileVersion` plus, since SGP.22 v2.7 §5.7.6,
`additionalEuiccProfilePackageVersions`). The SM-DP+ persists that set on the
session and resolves the UPP template against it, in order: the template pinned
on the order, the session template, the best template the version set supports,
the tenant default, the global default. A pinned template is authoritative: if it
is missing or incompatible the download fails instead of silently substituting
another template. A version-incompatible or unknown case fails at
`authenticateClient`/`getBoundProfilePackage` with `8.2.6/3.8` **before any
BoundProfilePackage segment is produced**, so the eUICC never rejects the package
at the end of the download. The failure is audited (`interface=es9p`,
`function=authenticateClient`, `outcome=Failed`, with `euiccProfileVersion`,
`supportedVersions`, `lowestTemplateVersion`) and counted in `/metrics`.

## Management API (admin listener)

A BSS/OSS-facing management API is served on the admin listener under
`/admin/api/v1` (JSON; no UI). It has no authentication and must be deployed on a
trusted network. `GET /admin/api/v1/openapi.json` serves the complete OpenAPI 3.0
description (schemas and error model included); the same document is checked in
at `internal/api/admin/openapi/openapi.json`. Every 2xx answer declares its response
schema there, and the test suite validates real responses against the declared
schema (`internal/api/admin/contract_test.go`).

| Area | Endpoints |
|---|---|
| Tenants | `GET/POST /tenants`, `GET/PATCH/DELETE /tenants/{id}` (quotas, `defaultUpp`, `callbackUrl`; `GET` returns `usage`, `DELETE` refuses with `409 tenant_in_use` unless `?force=true&reassignTo=<tenant\|"">` migrates the resources first — N3) |
| Profiles | `GET/POST /profiles`, `GET/PATCH/DELETE /profiles/{iccid}`, `POST /profiles/{iccid}/confirm\|cancel\|release`, `POST /profiles/{iccid}/activation-code` (`?rotate=1`), `GET /profiles/{iccid}/timeline` (orders + notifications + sessions + audit), `POST /profiles/bulk`, `GET /profiles/stats` |
| Download batches | `GET/POST /batches`, `GET/DELETE /batches/{id}`, `GET /batches/{id}/items`, `POST /batches/{id}/confirm\|cancel` |
| UPP registry | `GET/POST /upp`, `POST /upp/validate` (`valid` + `errors[]`/`warnings[]`), `POST /upp/render` (accepts `name` or an ad-hoc base64 `data`, N5), `GET/DELETE /upp/{name}`, `GET /upp/{name}/bytes`, `GET /upp/{name}/decoded`, `GET /upp/{name}/schema` (per-template `applicable`/`targets[]`/`requiredIn[]`, N4), `POST /upp/{name}/activate\|deactivate\|clone\|promote`, `GET /upp/{name}/versions`, `POST /upp/{name}/versions/{id}/restore` |
| Personalization | `GET /personalization`, `GET/PUT/DELETE /personalization/{iccid}` (`GET` accepts `?reveal=1` to include K/OPc), `POST /personalization/import`, `POST /personalization/pool/import` (IMSI+K/OPc, no ICCID), `GET /personalization/export` |
| ICCID pool | `GET /iccid-pool`, `GET /iccid-pool/stats`, `POST /iccid-pool/reserve\|release\|block`, `GET/POST /iccid-ranges`, `DELETE /iccid-ranges/{id}` |
| Export/import | `GET /profiles/export?format=csv\|json`, `POST /profiles/import` (`application/json` or `text/csv`) |
| Devices | `GET /eids` (profiles aggregated per eUICC) |
| Audit log | `GET /audit`, `GET /audit/stats` (`interface`, `function`, `subject`, `actor`, `outcome`, `tenant`, `from`/`since`, `to`/`until`, `groupBy`; `afterId`+`limit` switches to the monotonic incremental cursor `{items[].id, nextAfterId, hasMore}` — N1) |
| Notifications | `GET /notifications` (`iccid`, `eid`, `from`, `to`, `page`, `size`) |
| Callback queue | `GET /callbacks` (`state=pending\|sent\|failed\|dead`, `tenant`, `iccid`, `from`/`to`, `page`, `size`; `payload` is a parsed JSON object), `POST /callbacks/{id}/retry`, `POST /callbacks/retry-dead` (`{tenant,before,limit}`) — N2 |

The SM-DS admin listener exposes `GET /admin/api/v1/events` with `eid`,
`eventId`, `iccid`, `matchingId`, `tenant`, `status`
(`active|expired|deleted|any`), `from`/`since`, `to`/`until`, `sort`
(`registered_at|expires_at`, `-` prefix for ascending), `page` and `size`. N8
adds the write endpoints `POST /events` (an omitted `eventId` is generated as
`EVT-<token>`; re-use is `409 event_id_in_use`) and `DELETE /events/{id}`
(soft delete) for the edge cases where ES12 is not usable; the ES12 machine
interface remains the normal registration path.

### UPP validation scope (R1)

`POST /upp/validate` (and the value checks `POST /upp`, `clone`, `promote`,
`restore` run before accepting a template) perform, in order:

- **structure and constraints** (N13): the ProfileElement sequence and ordering,
  singletons, mandatory-services ↔ PE presence, AKA algorithm ↔ service bits,
  `identification` uniqueness, the `File` `doNotCreate`/`fileDescriptor` rules,
  and the `gfste[]` whitelist of the 14 V2.3.1 Annex B template OIDs;
- **the Annex A per-file defaults** (R1): for every file-system-template PE each
  file is matched to its Annex A row, and §8.3.3's template-modification rules
  are applied — a cell with no default ("X") must be supplied (`efFileSize` or
  content), `pinStatusTemplateDO`/`efFileSize`/`shortEFID`/`dfName` may only
  appear on the file kinds that allow them, the declared file type may not
  differ from the template's, and `shortEFID`/`fileID` are unique within their
  file-system scope;
- **ASN.1 value domains** (R1): only the `SIZE(...)` and fixed entry-count
  constraints listed here are enforced. ProfileHeader: `iccid` is 10 octets,
  `profileType` 1..100. `Fcp`: `fileDescriptor` 2..4, `fileID` 2, `dfName`
  5..16, `lcsi` 1, `securityAttributesReferenced` 1..3, `shortEFID` 0..1, and
  `ProprietaryInfo.specialFileInformation` 1, `fillPattern`/`repeatPattern`
  1..200. `PE-PINCodes.pinValue` and `PE-PUKCodes.pukValue` are 8 octets.
  `AlgoParameter.rotationConstants` 5, `xoringConstants` 80 and
  `authCounterMax` 3; `PE-AKAParameter.sqnOptions` 1, `sqnDelta` and
  `sqnAgeLimit` 6, `sqnInit` 32 entries of 6 octets. `PE-CDMAParameter`:
  `authenticationKey` 8, `ssd` 16, `hrpdAccessAuthenticationData` 2..32,
  `simpleIPAuthenticationData` 3..483, `mobileIPAuthenticationData` 5..957.

`valid:false` + `errors[]` are hard violations; `warnings[]` are advisories that
do not block registration (a changed fileID, an additional file that should have
been created with `PE-GenericFileManagement`, or a "Content Required" file whose
content is left to the create-command default — §9.1 explicitly allows that).

What is still **not** checked: the *content* of the Annex A default patterns
(they are not materialised) and the §9.9 access-rule table (the `ARR` column is
only carried as data). In addition, these V2.3.1 value domains are deliberately
outside the current scope (narrowing the claim rather than expanding the
validator): `AlgoParameter.algorithmOptions` `SIZE(1)`, the
`AlgoParameter.algorithmID` enumeration {1,2,3}, the `PINKeyReferenceValue` /
`PUKKeyReferenceValue` enumerations, and `ProfileHeader.eUICC-Mandatory-AIDs`
`version` `SIZE(2)`. Report to the caller only what the checks above cover.

### Tenant scoping and filters

Every list and write accepts `tenant`, with these exceptions: `GET /tenants` and
`GET /notifications` span all owners regardless, the batch/bulk writes derive the
owner from the payload, and the `/upp` and `/iccid-ranges` lists accept `tenant`
but not `page`/`size`. On a write the explicit body field wins over the query
parameter; a non-empty tenant must be registered, otherwise the answer is
`400 unknown_tenant`. Omit `tenant` to span all owners; pass an empty
value to select the **platform default** (`tenant_id IS NULL`), which is where
platform-owned resources and templates promoted with `/upp/{name}/promote`
live — it is a real owner, not an "unassigned" bucket. `POST /tenants` is
create-or-replace and is safe to call repeatedly, so a first deployment can
synchronise the whole carrier list with `POST` calls.

`GET /profiles` filters `iccid` by **prefix** match (a full match is a prefix of
itself); use `GET /profiles/{iccid}` for an exact lookup. Profiles additionally
accept `state`, `eid`, `externalRef`, `batchId`, `q` (substring), `from`, `to`,
`page`, `size` and `sort` (`created_at|updated_at|iccid|state|tenant|installed_at`,
`-` prefix for ascending). `GET /profiles/stats` also accepts
`groupBy=state|day|tenant|profile_type` (N7).

`GET /tenants/{id}` returns `usage`
(`profiles`, `templates`, `poolEntries`, `batches`, `personalization`) purely
from rsp42's own tables; it does **not** know about the caller's own records
(e.g. a `credential_assignments` table), so a caller that gates tenant deletion
on references has to count those separately and combine both.

### Quotas

`tenants.template_quota` is enforced when a new tenant template is created
(HTTP 409 `quota_exceeded`); replacing an existing template is always allowed.
`tenants.profile_quota` is enforced at allocation time on both the Admin API and
ES2+, where the answer is **`8.2.5/3.7`** (`CodeNoMoreProfileAvailable`), the
same code as an exhausted ICCID pool — profile quota and pool exhaustion are
deliberately indistinguishable on ES2+, and `GET /tenants/{id}` (`usage`) plus
`GET /iccid-pool/stats` are the way to tell them apart before sending an order.
An ICCID that is merely unusable (in use or blocked) answers `8.2.1/3.3`
instead.

### Response envelopes

List endpoints answer one of two shapes:

- **paginated** (`page`, `size`, `total`, `items`): `/profiles`, `/batches`,
  `/iccid-pool`, `/personalization`, `/callbacks`, `/notifications`, `/audit`
  (page mode), `/eids`;
- **unbounded** (`items`, `total`): `/tenants`, `/upp`, `/upp/{name}/versions`,
  `/iccid-ranges`.

Both always carry `items`; an empty list is `[]`, never `null`. `GET /audit`
switches to the incremental cursor shape (`items`, `nextAfterId`, `hasMore`, no
paging fields) when `afterId` is given (N1).

### Errors

Management API errors are `{"code": "...", "message": "..."}` with the HTTP
status. `code` is either derived from the HTTP status (`invalid_request`,
`not_found`, `conflict`, `unprocessable_entity`, `internal_error`,
`not_implemented`, `body_too_large`) or a named exception (`unknown_tenant`,
`quota_exceeded`, `tenant_in_use`, `saip_version_not_supported`, `invalid_upp`,
`event_id_in_use`, `idempotency_key_reused`, `idempotency_key_in_flight`).

A syntactically invalid ICCID (not 19/20 digits with a valid Luhn check digit) is
`400 invalid_request`; a well-formed ICCID that cannot be issued (in use,
blocked) is `409 conflict`. The same distinction applies on ES2+:
`downloadOrder` answers `8.1/1.2` for a malformed ICCID and `8.2.1/3.3` for one
that cannot be issued.

### Audit attribution

Audit rows carry the resolved `tenant` and an `actor`: the mTLS subject when
present, else the ES2+ `functionRequesterIdentifier` / ES12 caller OID, else the
fixed `esim42-backend` for the management API. Mutations are recorded with
`interface=admin`.

`function` is the invoked function name, not the URL path: the RSP interfaces
name the function in the last path segment (`downloadOrder`,
`authenticateClient`, `registerEvent`, …), so `GET /audit?function=downloadOrder`
matches and `GET /audit/stats?groupBy=function` groups by function. The ASN.1
binding carries every function on the single `/gsma/rsp2/asn1` path, so its
handler names the function it decoded; management-API rows keep their path.
`detail` carries machine-readable extras: `requestId`, the C2
`warning=profileType-unparsed`, and the tenant-attribution
`warning=unmapped` + `requester` (see Tenant attribution).

### Metrics

`GET /metrics` (Prometheus text format) on the admin listener exposes the
following vocabulary (declared per emitting package, so a typo is a loud
failure rather than a missing series):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rsp42_downloads_total` | counter | `tenant`, `point`, `status` | one per outbound ES2+ progress notification, i.e. per download/install outcome point (1, 2, 3, 4, 17) |
| `rsp42_acr_requests_total` | counter | `tenant`, `outcome` | ES2+ HandleAcrRequest confirmations (`allowed`/`refused`/`error`) |
| `rsp42_euicc_v3_capable_total` | counter | `tenant` | eUICCs advertising a SAIP version at or above the V3 baseline (N11) |
| `rsp42_profile_version_not_supported_total` | counter | `tenant` | downloads refused because no template matched the eUICC's versions (N12) |
| `rsp42_es2p_profile_type_unparsed_total` | counter | `tenant` | `profileType` that did not resolve to a template (C2) |
| `rsp42_es2p_tenant_unmapped_total` | counter | — | ES2+ calls whose requester was not mapped to a tenant |
| `rsp42_es12_register_failures_total` | counter | `tenant` | SM-DS event registration/deletion failures |
| `rsp42_es2p_callback_queue` | gauge | `status` | outbound callback rows by state |
| `rsp42_iccid_pool` | gauge | `state` | ICCID pool entries by state |
| `rsp42_smds_events` | gauge | `status` | SM-DS event records by lifecycle status (`active`/`expired`/`deleted`) |
| `rsp42_session_gc_total`, `rsp42_iccid_reservation_gc_total`, `rsp42_smds_event_gc_total` | counter | — | reclamation counters |

There is no HTTP latency histogram (N9, deferred): measure rsp42 call latency on
the caller side.

## Admin CLI

`rsp42 admin migrate|rekey|profile|session|gc|upp|iccid|personalization|activation-code|smds|es2p|mock-operator|version`
(see `rsp42 admin help`).
