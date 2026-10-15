# Architecture

`rsp42` implements an SM-DP+ and an SM-DS for GSMA SGP.22 (RSP). Both roles are
provided by a single `rsp42` binary; they are independent processes with equal
standing and their own configuration sections, TLS listeners and SQLite
databases.

## Processes

- `rsp42 smdpp` — SM-DP+ (ES9+ `:8443`, ES2+ `:8444`, admin `:9000`).
- `rsp42 smds` — SM-DS (ES11 `:9443`, ES12 `:9444`, admin `:9100`).
- `rsp42 admin …` — operational tooling.

Their configuration sections are peers: `smdpp.enabled` / `smdpp.server` (ES9+/ES2+
/admin listeners, `smdpp.fqdn`, …) and `smds.enabled` / `smds.server` (ES11/ES12/
admin listeners, `smds.role`, `smds.fqdn`, …). Neither role has a default; the
container selects one via `RSP42_ROLE`.

## Packages

```
cmd/rsp42                     single entry point
internal/config               YAML + env config (per-section validation, RSP42_* overrides)
internal/logging              slog setup
internal/version              build metadata (-ldflags injected)
internal/hexutil              uppercase-hex rendering — leaf, no dependencies
internal/iccid                ICCID text helpers (padding, Luhn, nibble-swapped BCD) — leaf
internal/saipver              SAIP version value type — leaf, no dependencies
internal/asn1                 BER-TLV: raw-preserving parser + mutable Node tree + raw writer
internal/rsp                  hand-written SGP.22 message codecs + signing helpers
internal/rsp/status           SGP.22 §5.2.6 status-code vocabulary — leaf
internal/crypto               ECDSA raw, X9.63 KDF, SCP03t (BSP), BPP protection
internal/cert                 certificate chain, roles/policies, EUM constraints
internal/kms                  file KMS: PEM keys + AES-256-GCM (SignerLoader / Sealer)
internal/saip                 SAIP ProfileElement model (parse/edit/encode, PE registry)
internal/saip/personalization personalization engine + data sources
internal/uppinspect           read-only UPP projection + template field catalog
internal/store                SQLite + goose migrations + repositories
internal/service              business logic (CMAE, orders, sessions, SM-DS, …)
internal/api                  HTTP routers for ES2+/ES9+/ES11/ES12
internal/api/common           shared JSON-binding types and response writers
internal/api/middleware       shared HTTP middleware (audit, idempotency, limits)
internal/api/asn1bind         shared ASN.1-binding plumbing for ES9+/ES11
internal/api/adminhttp        shared management-API HTTP conventions (error model, paging)
internal/api/openapi          the management-API OpenAPI document, shared by both surfaces
internal/api/admin            SM-DP+ management API
internal/api/dsadmin          SM-DS management API (event records)
internal/audit                structured audit sinks
internal/activationcode       activation codes + QR
internal/client/es2p          ES2+ outbound clients (callbacks, callback queue, operator client)
internal/client/es12          ES12/ES15 outbound client
internal/mockoperator         the development mock ES2+ operator (dev-only command + tests)
internal/uppio                UPP directory ingestion
internal/testutil             test-only helpers (not linked into the binary)
internal/archcheck            test-only dependency/containment guard (no production code)
```

### Dependency direction

```
cmd/rsp42 → cli ─┬→ api ─┐
                 │       ├→ service ─┐
                 │       │           ├→ {rsp, saip, crypto, cert, kms, store,
                 │       │           │    config, logging, metrics, activationcode}
                 │       └───────────┘
                 └→ cli/admin

leaf (no rsp42 imports): asn1, hexutil, iccid, saipver, kms, logging, metrics,
                         rsp/status, version
```

`internal/archcheck` asserts these edges and the containment rules below; a
structural regression fails `go test`.

Rules the tree is expected to keep:

- **Nothing below imports anything above.** `asn1`, `hexutil`, `iccid`,
  `saipver`, `rsp/status`, `kms`, `logging`, `metrics` and `version` are leaves;
  in particular no interface package imports `service` or `api`, and `cert` (a
  primitive) does not import `config` — the config-to-`cert.Options` mapping
  lives in the composition root (`cli/kmsload.go`).
- **`store` and `config` never import `rsp`.** A comparable pair or a Luhn check
  digit is not a wire concern: the SAIP version type lives in `saipver` and the
  ICCID helpers in `iccid`. This is what keeps the persistence layer independent
  of the protocol codecs.
- **The HTTP layer depends on consumer-defined interfaces, not on the concrete
  services or repositories.** Each handler package has a `deps.go` naming the
  behaviour it needs: `api/admin` (per aggregate), `api/dsadmin`,
  `api/es2plus` (`Orders`, `Inventory`, `TenantResolver`, `Registrar`),
  `api/es9plus` (`CMAE`, `Notifier`), `api/es11` (`DS`), `api/es12`
  (`EventRegistrar`, `TenantResolver`), `api/middleware` (`IdempotencyStore`),
  `audit` (`AuditSink`), `client/es2p` (`QueueStore`) and `service`
  (`ProfileStore`, `SessionStore`, `EventStore`, `RegistrationStore`,
  `NotificationStore`, `UPPStore`, `PersonalizationStore`, `AuditSink`). Each
  declares a compile-time assertion that the concrete type satisfies it.
  A nil interface is not callable where a typed nil pointer used to be tolerated
  by a nil-checking receiver, so the two optional resolvers are guarded
  explicitly.
- **`service` keeps its dependency-inversion tests**, but not all of its tests
  are DB-free: `service/dip_test.go` exercises the ports on in-memory fakes,
  while several other service tests open a real SQLite store.
- **Repositories are only wired in the composition root** (`cmd` → `cli`). The
  management API also validates its dependency set at startup
  (`admin.Handler.Validate`, `dsadmin.Config.Validate`) instead of answering 501
  or panicking at request time.
- **`bertlv` is imported by exactly one file** (`internal/asn1/construct.go`):
  `asn1.Tag` is a plain byte slice and `asn1.Builder` is rsp42's own opaque type,
  so replacing the BER-TLV library is a change confined to that package. The two
  shapes `bertlv` cannot express (a content length above 64 KiB, a constructed
  tag with pre-encoded content) are handled by `asn1.RawTagged`, the single place
  that works around them. `internal/archcheck` pins the single-importer rule.
- **Outbound HTTP clients live outside the server handler packages**: `client/es2p`
  (ES2+ callbacks and the operator client) and `client/es12` (ES12/ES15).
  A handler package only serves its interface, and `service` imports no HTTP
  server/client package of its own.
- **The filesystem is touched at startup and by explicit import/export paths**:
  startup (`cli/listener.go`, certificates, KMS keys), the UPP directory importer
  (`internal/uppio`), the audit file sink, the personalization CSV importer
  (`saip/personalization/csv.go`, reached from `rsp42 admin personalization
  import`) and `rsp42 admin activation-code --qr`. A *serving* request path never
  reads a template or a credential from disk.
- **`internal/testutil` is test-only.** Only `_test.go` files import it, so it is
  not linked into the binary; `internal/archcheck` fails the build if a
  non-test file imports it. The ES2+ mock that the dev-only
  `admin mock-operator` command runs therefore lives outside it, in
  `internal/mockoperator`, which states that it is a development component.

### Directory responsibilities

| Directory | Belongs there | Does not belong there |
|---|---|---|
| `internal/asn1` | BER-TLV reader (`TLV`), editable tree (`Node`), builder and tag helpers | Protocol messages, SAIP knowledge, I/O |
| `internal/rsp` | Hand-written SGP.22 messages and codecs, one file per family (`download`, `notification`, `cancel`, `signed`, `euicc_info`, `response_decode`), signing helpers, the §4.1 server-address match | HTTP, storage, SAIP personalization, the status vocabulary (that is `rsp/status`) |
| `internal/saip` | ProfileElement model and registry, header codec/policy (`header.go`, `header_services.go`, `gfste.go`), template table, V2.3.1 constraints | Storage, HTTP, version policy (that is `saipver` + `service`) |
| `internal/saip/personalization` | Data model, engine, per-field appliers, field codecs | Storage, HTTP |
| `internal/crypto`, `internal/cert`, `internal/kms` | Primitives (`bsp`, `bpp`, `ecdsa`, `kdf`), certificate loading/validation/selection, key provider | Business logic |
| `internal/store` | One repository per aggregate, migrations, `errors.go`, `sqlutil.go` | Domain rules (allocation policy, version ordering), protocol types |
| `internal/service` | Orchestration and policy: CMAE, orders, sessions, inventory, personalization, SM-DS, notifications; consumer-defined ports in `interfaces.go` | SQL, filesystem I/O (importing is `internal/uppio`), HTTP (that is `client/es12`) |
| `internal/api/common`, `adminhttp`, `asn1bind` | Shared HTTP conventions: SGP.22 envelopes, the management-API error model and paging, the §6.6 ASN.1 binding plumbing | Resource-specific handler logic |
| `internal/api/es9plus`, `es11`, `es12`, `es2plus` | One HTTP interface each: decode, authorize, call `service`, envelope; the seams it needs in its own `deps.go` | Outbound clients, cross-interface shared logic |
| `internal/api/admin`, `internal/api/openapi` | The SM-DP+ management surface, and the OpenAPI document both surfaces filter | The SM-DS surface, client code |
| `internal/api/dsadmin` | The SM-DS management surface (event records) | SM-DP+ resources |
| `internal/client/es2p`, `internal/client/es12` | Outbound clients: ES2+ (callbacks, callback queue, operator client) and ES12/ES15 | Server handlers |
| `internal/cli` | Composition roots (`smdpp_graph.go`, `smds.go`), listeners/TLS, lifecycle, the command tables and their shared wiring (`kmsload.go`) | Business logic, data access |
| `internal/cli/admin` | The `rsp42 admin` command implementations | The role composition roots |
| `internal/uppinspect` | The read-only UPP projection and the template field catalog | Storage, HTTP, orchestration |
| `internal/uppio` | The only UPP directory ingestion path | Runtime resolution (that is `store` + `service`) |
| `internal/testutil`, `internal/archcheck` | Test-only helpers, and the guard that pins the layer/containment rules | Anything linked into the binary |

`cmd/rsp42` is a three-line entry point; everything else is reached from
`internal/cli`.

## Design notes

- **Composition over duplication**: the SM-DP+ and SM-DS share the Common Mutual
  Authentication handshake through `service/cmaeCore` (`cmae_core.go`). Each role
  injects its own signer/identity and maps the core's typed errors to its
  interface-specific status codes (ES9+ `8.x` vs ES11 `8.9.x`).
- **Consumer-side interfaces (dependency inversion)**: every layer that touches
  persistence declares the seam it uses (see *Dependency direction* above); the
  concrete SQLite repositories and `cert.Manager` satisfy them, so a handler or a
  service can be exercised without a database.
- **Small, cohesive files**: a file holds one job. RSP messages are split by
  family, store repositories one per aggregate (`errors.go` and `sqlutil.go`
  beside them), SAIP header codec/policy/GFSTE are separate files, the SM-DP+
  object graph is its own file (`cli/smdpp_graph.go`), and each admin CLI command
  has its own file. A directory never mixes roles from the table above.
- **One source of truth per contract**: the management-API contract is
  `internal/api/openapi/openapi.json`, and the test suite validates real
  responses against the schema the document declares for each operation; the
  metric vocabulary is declared by the packages that emit it
  (`service.DescribeMetrics`, `es2plus.DescribeMetrics`).
- **Explicit**: no global mutable state; sensitive session columns have a
  dedicated field/column; status codes are named `status.Code` values
  (`internal/rsp/status`).
- **Fixed deployment shape (deliberate)**: SQLite only, one process per database
  file, one replica. There is no storage abstraction for other backends, no
  leader election and no rsp42-side rate limiting; tenant attribution on ES2+ is
  a `functionRequesterIdentifier` mapping rather than per-carrier certificates.
  These are decided non-goals, recorded in `docs/esim42-integration-gaps.md` §8.4.
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
