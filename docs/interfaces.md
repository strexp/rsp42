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

## Status codes

Failures use `header.functionExecutionStatus.status = "Failed"` with
`statusCodeData{subjectCode, reasonCode, message}` (SGP.22 §5.2.6), e.g.
`8.8.1/3.8` invalid SM-DP+ address, `8.8.2/3.1` unsupported CI key,
`8.10.1/3.9` unknown transaction, `8.2.7/6.4` confirmation code invalid,
`8.9.5/3.3` EventID in use, `8.9.5/3.9` event not found.

## Management API (admin listener)

A BSS/OSS-facing management API is served on the admin listener under
`/admin/api/v1` (JSON; no UI). It has no authentication and must be deployed on a
trusted network. `GET /admin/api/v1/openapi.json` returns a compact description.

| Area | Endpoints |
|---|---|
| Profiles | `GET/POST /profiles`, `GET/PATCH/DELETE /profiles/{iccid}`, `POST /profiles/{iccid}/confirm\|cancel\|release`, `POST /profiles/{iccid}/activation-code`, `GET /profiles/{iccid}/timeline`, `POST /profiles/bulk` |
| Download batches | `GET/POST /batches`, `GET/DELETE /batches/{id}`, `GET /batches/{id}/items`, `POST /batches/{id}/confirm\|cancel` |
| UPP registry | `GET/POST /upp`, `GET/DELETE /upp/{name}`, `GET /upp/{name}/bytes`, `GET /upp/{name}/decoded`, `POST /upp/{name}/activate\|deactivate` |
| Personalization | `GET /personalization`, `GET/PUT/DELETE /personalization/{iccid}` (`?reveal=1` includes K/OPc), `POST /personalization/import`, `GET /personalization/export` |
| ICCID pool | `GET /iccid-pool`, `GET /iccid-pool/stats`, `POST /iccid-pool/reserve\|release\|block`, `GET/POST /iccid-ranges`, `DELETE /iccid-ranges/{id}` |
| Export/import | `GET /profiles/export?format=csv\|json`, `POST /profiles/import` |
| Audit log | `GET /audit` (`interface`, `function`, `subject`, `actor`, `outcome`, `since`, `until`, `page`, `size`) |

The SM-DS admin listener exposes a read-only `GET /admin/api/v1/events`
(`eid`, `eventId`, `page`, `size`); event writes remain the ES12 machine
interface.

Profile listings accept `state`, `eid`, `iccid` (prefix), `q` (substring),
`page`, `size`, `sort`. Mutations are recorded in `audit_log` with
`interface=admin`.

## Admin CLI

`rsp42 admin migrate|rekey|profile|session|gc|upp|personalization|activation-code|smds|es2p|mock-operator`
(see `rsp42 admin help`).
