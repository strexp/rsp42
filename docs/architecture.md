# Architecture

`rsp42` implements an SM-DP+ and an SM-DS for GSMA SGP.22 (RSP). Both roles are
provided by a single `rsp42` binary; they are independent processes with equal
standing and their own configuration sections, TLS listeners and SQLite
databases.

## Processes

- `rsp42 smdpp` — SM-DP+ (ES9+ `:8443`, ES2+ `:8444`, admin `:9000`).
- `rsp42 smds` — SM-DS (ES11 `:9443`, ES12 `:9444`, admin `:9100`).
- `rsp42 admin …` — operational tooling.

## Packages

```
cmd/rsp42                     single entry point
internal/config               YAML + env config, strict validation
internal/logging              slog setup
internal/asn1                 BER-TLV: raw-preserving parser + mutable Node tree
internal/rsp                  hand-written SGP.22 message codecs + signing helpers
internal/crypto               ECDSA raw, X9.63 KDF, SCP03t (BSP), BPP protection
internal/cert                 certificate chain, roles/policies, EUM constraints
internal/kms                  file KMS: PEM keys + AES-256-GCM
internal/saip                 SAIP ProfileElement model (parse/edit/encode)
internal/saip/personalization personalization engine + data sources
internal/store                SQLite + goose migrations + repositories
internal/service              business logic (CMAE, orders, sessions, SM-DS, …)
internal/api                  HTTP routers and handlers (ES2+/ES9+/ES11/ES12)
internal/api/admin            management API (profiles, batches, UPP, personalization)
internal/audit                structured audit sinks
internal/activationcode       activation codes + QR
```

Package dependencies flow `cmd → api/service → {rsp, saip, crypto, cert, kms,
store, config, logging}`; the low-level packages never depend on `api`.

## Design notes

- **Composition over duplication**: the SM-DP+ and SM-DS share the Common Mutual
  Authentication handshake through `service/cmaeCore` (`cmae_core.go`). Each role
  injects its own signer/identity and maps the core's typed errors to its
  interface-specific status codes (ES9+ `8.x` vs ES11 `8.9.x`).
- **Consumer-side interfaces (dependency inversion)**: `service` defines the
  small interfaces it needs (`ProfileStore`, `SessionStore`, `EventStore`,
  `RegistrationStore`, `NotificationStore`, `certProvider`); the concrete SQLite
  repositories and `cert.Manager` satisfy them. `api/es2plus` depends on
  `service.ProfileStore`/`OrderAuditor`, not on `store`.
- **Small, cohesive files**: RSP messages are split by family (`session`/
  `download`/`notification`/`cancel`), store repositories one per aggregate,
  and the CLI is split into `server`/`smdpp`/`smds`/`admin*`.
- **Explicit**: no global mutable state; sensitive session columns have a
  dedicated field/column; status codes are named `rsp.Code` values.
- **UPP registry**: SAIP templates live in the `upp_templates` table (blob +
  SAIP version + SHA-256) and are resolved through `service.UPPStore`; they are
  seeded with `rsp42 admin upp import --dir` (no `upp_dir` in the config), so the
  SM-DP+ does not touch the filesystem at request time.
- **Per-ICCID personalization**: values live in the `personalization` table and
  are resolved through `service.PersonalizationResolver` (K/OPc encrypted at
  rest); seeded with `rsp42 admin personalization import --file`. This replaced a
  single global cursor that raced under concurrent downloads.


## Download flow (ES2+ → ES9+)

1. `ES2+.DownloadOrder` reserves an ICCID (`Allocated`, or `Linked` with an EID).
2. `ES2+.ConfirmOrder` assigns a MatchingID, stores `SHA256(CC)` if a
   confirmation code is supplied, and moves the profile to `Confirmed` or
   `Released`; when an SM-DS address is configured an ES12 event is registered.
3. `ES9+.InitiateAuthentication` → `authenticateClient` → `getBoundProfilePackage`
   (Common Mutual Authentication, then real-time BPP generation with SCP03t and
   the operator-supplied personalization values applied to the UPP).
4. `ES9+.HandleNotification` processes the installation result and updates the
   profile lifecycle and operator callbacks.

## Event flow (ES2+ → ES12 → ES11)

`ConfirmOrder` registers an event (`EVT = MatchingID`) at the SM-DS. An LPA
discovers it over ES11 (empty MatchingID → all events for the EID; or a specific
EventID). An Alternative SM-DS cascades registrations to the Root SM-DS over
ES15, rolling back locally on failure.
