# Interfaces

All interfaces use the SGP.22 JSON binding (`Content-Type: application/json`).
Binary fields are base64-encoded ASN.1 structures; `transactionId` is an
uppercase hex string. Synchronous functions always return HTTP 200 with a
`header.functionExecutionStatus`; notification functions return HTTP 204.

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

## Admin

`rsp42 admin migrate|rekey|profile|session|activation-code|smds|es2p|mock-operator`
(see `rsp42 admin help`).
