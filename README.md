# rsp42

An SM-DP+ and SM-DS implementation for GSMA SGP.22 (RSP), written in Go.

The project targets the SGP.26 v3 test certificate ecosystem and implements:

- **ES9+** (LPA ↔ SM-DP+): `initiateAuthentication`, `authenticateClient`,
  `getBoundProfilePackage`, `handleNotification`, `cancelSession`.
- **ES2+** (Operator ↔ SM-DP+): `downloadOrder`, `confirmOrder`, `cancelOrder`,
  `releaseProfile`, `handleDownloadProgressInfo`, `handleAcrRequest`, plus an
  ES2+ client library and CLI.
- **ES11 / ES12 / ES15** (SM-DS, Root and Alternative roles): mutual
  authentication, event registration/cascade/retrieval/deletion.
- Real-time Bound Profile Package generation (SCP03t) and full SAIP
  personalization.

Both HTTP bindings are implemented: the **JSON binding** (SGP.22 §6.5) and the
**ASN.1 binding** (SGP.22 §6.6, `/gsma/rsp2/asn1`).

## Status

Under active development.

## Layout

```
cmd/rsp42        the rsp42 binary: `smdpp`, `smds` and `admin` subcommands
internal/        implementation packages
config/          example configuration
scripts/         test-data tooling
testdata/        static test material (see testdata/README.md)
```

## Prerequisites

- Go (latest stable; currently 1.27)
- `openssl` (only for the test-data scripts)

## Build and test

```sh
make build        # builds bin/rsp42 (provides both the smdpp and smds roles)
make test         # runs the unit/component tests
make vet
make lint         # requires golangci-lint
```

## Test data

The test suite needs the SGP.26 certificates and the TS.48 UPP templates, which
are generated into `testdata/` (and are not committed). `make testdata` fetches
them from public upstreams by default; override `SGP26_SRC` / `UPP_SRC` with
local paths to use material you already have:

```sh
make testdata
# or:
make testdata SGP26_SRC=/path/SGP.26_v3.0.2-2026_files_v2.zip UPP_SRC=/path/to/upp
```

See `testdata/README.md` for details.

## Running

The `rsp42` binary provides both roles with equal standing:

```sh
cp config/config.example.yaml config/config.yaml
make seed                                        # import UPP templates + personalization (db/)
./bin/rsp42 smdpp --config config/config.yaml    # SM-DP+ role (ES9+ :8443, ES2+ :8444)
./bin/rsp42 smds  --config config/config.yaml    # SM-DS  role (ES11 :9443, ES12 :9444)
```

UPP templates and personalization live in the database and are seeded with the
CLI (`make seed`); they can be re-imported at any time without a restart.

Health endpoints are exposed on the admin port (`/healthz`, `/readyz`), which
also serves a BSS/OSS-facing management API under `/admin/api/v1` (profiles,
download batches, UPP registry, personalization; see `docs/interfaces.md` and
`GET /admin/api/v1/openapi.json`). It has no authentication; deploy it on a
trusted network.

Configuration is a single YAML file; every value can be overridden through
`RSP42_`-prefixed environment variables (see `config/config.example.yaml`).

## Container

```sh
docker build -t rsp42 .
docker run -v $PWD/config/config.yaml:/etc/rsp42/config.yaml rsp42 smdpp
```

The image preinstalls the dn42 root CA (see `docs/operations.md`).

## Documentation

- `docs/architecture.md` — design and package layout.
- `docs/interfaces.md` — HTTP/JSON interface reference.
- `docs/operations.md` — deployment, databases, certificates, container.
- `docs/coverage.md` — SGP.22 function/requirement coverage.
- `docs/dependencies.md` — dependency register.
- `testdata/README.md` — test data provenance.

## License

AGPL-3.0
