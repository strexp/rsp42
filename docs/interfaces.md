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
`authenticateClient` request: `{transactionId, authenticateServerResponse}`.
`getBoundProfilePackage` request: `{transactionId, prepareDownloadResponse}`.

## ES2+ (SM-DP+, Operator-facing, mTLS)

`POST /gsma/rsp2/es2plus/{downloadOrder,confirmOrder,cancelOrder,releaseProfile,
handleDownloadProgressInfo,handleAcrRequest}`. Requests carry
`header{functionRequesterIdentifier, functionCallIdentifier}`.

### Tenant attribution

The caller's `header.functionRequesterIdentifier` is mapped to a tenant by
`smdpp.es2p.requester_tenants` (SGP.22 §6.5.1.3 imposes no format on the field).
An unmapped requester falls back to the platform-default tenant (`""`) and the
request is audited with the incremented `unmapped` warning. A tenant may only
operate on its own ICCIDs: using another tenant's ICCID answers `8.2.1/1.2`, and
using another tenant's Profile Type/template answers `8.2.5/1.2`.

### Profile/template selection

`downloadOrder.profileType` is "content free information defined by the
Operator" (§6.5.2.1). rsp42 interprets `"<tenant>/<template>"` as a
tenant-local template selector; any other value stays opaque and template
resolution falls back to the eUICC's advertised SAIP version, then the tenant
default, then `profiles.default_upp`. A caller may never select another
tenant's template. At download time the resolution order is: template pinned on
the order, session template (eUICC version), tenant default, global default;
there is no "any template" fallback.

### Resend semantics

Per Table 24 NOTE, a repeated `downloadOrder` naming an ICCID that already
exists in `Allocated`/`Linked` with the same tenant, `profileType` and EID
answers `Executed-Success` with that ICCID and performs no further action, so an
operator retry after a lost response is safe.

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
| 1 | eligibility/authorisation check failure |
| 2 | confirmation code failure |
| 3 | download result |
| 4 | installation result |
| 17 | activation code retrieval |

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

ES2+ distinguishes four frequently confused conditions so the operator can
branch correctly:

| Condition | Code |
|---|---|
| ICCID unknown to the SM-DP+ | `8.2.1/3.9` |
| Profile Type / template unknown | `8.2.5/3.9` |
| Profile Type / template (or ICCID) not allowed for the caller | `8.2.5/1.2` / `8.2.1/1.2` |
| Mandatory request element missing (e.g. `iccid`) | `8.1.1/2.2` |
| `confirmOrder.eid` disagrees with the download order | `8.1.1/3.10` |
| No template compatible with the eUICC's SAIP versions (N12) | `8.2.6/3.8` + readable message |

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
at `internal/api/admin/openapi.json`.

| Area | Endpoints |
|---|---|
| Tenants | `GET/POST /tenants`, `GET/PATCH/DELETE /tenants/{id}` (quotas, `defaultUpp`, `callbackUrl`; `GET` returns `usage`, `DELETE` refuses with `409 tenant_in_use` unless `?force=true&reassignTo=<tenant\|"">` migrates the resources first — N3) |
| Profiles | `GET/POST /profiles`, `GET/PATCH/DELETE /profiles/{iccid}`, `POST /profiles/{iccid}/confirm\|cancel\|release`, `POST /profiles/{iccid}/activation-code` (`?rotate=1`), `GET /profiles/{iccid}/timeline` (orders + notifications + sessions + audit), `POST /profiles/bulk`, `GET /profiles/stats` |
| Download batches | `GET/POST /batches`, `GET/DELETE /batches/{id}`, `GET /batches/{id}/items`, `POST /batches/{id}/confirm\|cancel` |
| UPP registry | `GET/POST /upp`, `POST /upp/validate` (`valid` + `errors[]`/`warnings[]`), `POST /upp/render` (accepts `name` or an ad-hoc base64 `data`, N5), `GET/DELETE /upp/{name}`, `GET /upp/{name}/bytes`, `GET /upp/{name}/decoded`, `GET /upp/{name}/schema` (per-template `applicable`/`targets[]`/`requiredIn[]`, N4), `POST /upp/{name}/activate\|deactivate\|clone\|promote`, `GET /upp/{name}/versions`, `POST /upp/{name}/versions/{id}/restore` |
| Personalization | `GET /personalization`, `GET/PUT/DELETE /personalization/{iccid}` (`?reveal=1` includes K/OPc), `POST /personalization/import`, `POST /personalization/pool/import` (IMSI+K/OPc, no ICCID), `GET /personalization/export` |
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

### Tenant scoping and filters

Every list and write accepts `tenant`. On a write the explicit body field wins
over the query parameter; a non-empty tenant must be registered. Omit `tenant`
to span all owners; pass an empty value to select the platform default
(`tenant_id IS NULL`). Profiles additionally accept `state`, `eid`, `iccid`
(prefix), `externalRef`, `batchId`, `q` (substring), `from`, `to`, `page`,
`size` and `sort` (`created_at|updated_at|iccid|state|tenant|installed_at`, `-`
prefix for ascending). `GET /profiles/stats` also accepts
`groupBy=state|day|tenant|profile_type` (N7).

### Quotas

`tenants.template_quota` is enforced when a new tenant template is created
(HTTP 409 `quota_exceeded`); replacing an existing template is always allowed.
`tenants.profile_quota` is enforced at allocation time on both the Admin API and
ES2+ (the ES2+ answer is `8.2.1/3.8`).

### Errors

Management API errors are `{"code": "...", "message": "..."}` with the HTTP
status. Codes are stable and machine-readable (`invalid_request`, `not_found`,
`conflict`, `not_implemented`, `internal_error`, `unknown_tenant`,
`idempotency_key_reused`, `idempotency_key_in_flight`).

### Audit attribution

Audit rows carry the resolved `tenant` and an `actor`: the mTLS subject when
present, else the ES2+ `functionRequesterIdentifier` / ES12 caller OID, else the
fixed `esim42-backend` for the management API. Mutations are recorded with
`interface=admin`.

### Metrics

`GET /metrics` (Prometheus text format) on the admin listener exposes download
success/failure counters by tenant, confirmation-code failures, callback queue
depth, ICCID pool gauges, and session/event GC counters.

## Admin CLI

`rsp42 admin migrate|rekey|profile|session|gc|upp|personalization|activation-code|smds|es2p|mock-operator`
(see `rsp42 admin help`).
