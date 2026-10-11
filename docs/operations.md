# Operations

## Build and run

```sh
make build
cp config/config.example.yaml config/config.yaml
./bin/rsp42 smdpp --config config/config.yaml   # SM-DP+
./bin/rsp42 smds  --config config/config.yaml   # SM-DS
```

## Databases

SQLite (pure Go driver), migrated automatically at startup via goose. The
schema is a single current-schema migration (`internal/store/migrations/00001_init.sql`);
there is no legacy/back-compat handling. Separate DSNs for the SM-DP+
(`profiles.store.dsn`) and SM-DS (`smds.store.dsn`). Apply migrations manually
with `rsp42 admin migrate [--db dp|ds]`.

Sensitive columns (`cc_hash`, `server_challenge`, `smdp_ot_sk`,
`shared_secret`) are encrypted with AES-256-GCM using the KMS key-encryption key.
The KEK is given either as `kms.kek_hex` (64 hex characters) or via the file
`kms.kek_file` (exactly 32 bytes); it must be protected and backed up, and it is
required to read any persisted session material. Rotate it with
`rsp42 admin rekey --new-kek NEW`.

## Certificates

Default material is the SGP.26 v3.0.2 Variant O test set under `testdata/sgp26`
(run `make testdata` once). Startup validates the chain, role/policy OIDs, key
usage, SAN OIDs/DNS and validity for the configured curve. The test DPtls/DStls
certificates are valid until 2027-03; `certs.allow_expired_test_certs` downgrades
expiry to a warning (test only).

`rsp42 smdpp` uses `CERT.DPauth`/`CERT.DPpb` for signatures and `CERT.DP.TLS`
for TLS. `rsp42 smds` uses `CERT.DSauth` and `CERT.DS.TLS`. ES2+/ES12/ES15 use
mutual TLS; ES9+/ES11 use server-authenticated TLS.

## Container image

The multi-stage `Dockerfile` produces an `alpine` runtime image. It preinstalls
the **dn42 root CA** (`deploy/dn42-root-ca.crt`, from
<https://wiki.dn42/services/ca/Certificate-Authority/>) so outbound TLS to
`*.dn42` services validates, and bundles `config.example.yaml` at
`/etc/rsp42/config.example.yaml`.

```sh
docker build -t rsp42 .
docker run -v $PWD/config/config.yaml:/etc/rsp42/config.yaml rsp42 smdpp
```

## Health and shutdown

`/healthz` and `/readyz` on the admin port. SIGINT/SIGTERM trigger a graceful
shutdown (15s grace). Request bodies are capped (1 MiB control plane, 4 MiB
ES9+).

## Administrative tasks

```sh
rsp42 admin profile list|show        # inventory (not users)
rsp42 admin session gc               # remove expired sessions
rsp42 admin activation-code --fqdn F --matching-id M [--qr out.png]
rsp42 admin smds event list|delete
rsp42 admin es2p downloadOrder|confirmOrder|cancelOrder|releaseProfile
rsp42 admin mock-operator            # test-only operator stub
```

## Known limitations

Online CRL/OCSP is out of scope (expiry is validated, revocation is not). The
JSON binding is implemented; the ASN.1 binding is not. Some SGP.22 extensibility
features (full SAIP template table / GFSTE recomputation, PPR population,
`otherCertsInChain`, ACR caller-side `HandleAcrRequest`) are partial; see
`docs/coverage.md`.
