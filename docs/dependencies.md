# Dependencies

Every build dependency is recorded here with its source, version, license and
purpose.

## Dependency policy

- **Admission**: a build dependency must be a mature project — widely used,
  actively maintained, with a stable release tag and an MIT/BSD/Apache-2.0
  license. Low-star, tag-less, unmaintained, or license-less projects are not
  admitted.
- **No generated-code dependencies**: the SGP.22 RSP codec (`internal/rsp`,
  including the ASN.1 binding envelopes of §6.6) and SAIP model
  (`internal/saip`) are hand-written.
- **Record**: every dependency is listed here with source/tag/license/purpose.
- **Licenses**: GPL/AGPL are only allowed for separate, non-linked processes;
  code from repositories without a declared license is never copied.
- **External tools**: LPA implementations and protocol tooling are test
  fixtures/references only and are not part of the build.

## Direct dependencies

| Module | Version | License | Purpose |
|---|---|---|---|
| `github.com/euicc-go/bertlv` | v0.2.4 | MIT | BER-TLV base (multi-byte tags, raw bytes, primitive codec) |
| `github.com/aead/cmac` | v0.0.0-20160719120800-7af84192f0b1 | MIT | AES-CMAC for SCP03t (BSP) |
| `github.com/go-chi/chi/v5` | v5.3.2 | MIT | HTTP routing |
| `modernc.org/sqlite` | v1.60.1 | BSD-3-Clause | Pure-Go SQLite driver |
| `github.com/pressly/goose/v3` | v3.28.0 | MIT | Database migrations |
| `github.com/spf13/viper` | v1.21.0 | MIT | Configuration loading |
| `gopkg.in/yaml.v3` | v3.0.1 | MIT/Apache-2.0 | YAML parsing |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | Transaction IDs, request IDs |
| `github.com/stretchr/testify` | v1.12.1 | MIT | Test assertions |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | BSD-3-Clause | SGP.22 JSON schema contract tests |
| `github.com/skip2/go-qrcode` | v0.0.0-20200617195104-da1b6568686e | MIT | Activation-code QR rendering |

The Go standard library (`crypto/*`, `net/http`, `log/slog`, `encoding/*`) covers
curves, signatures, TLS, AES-CBC and logging.

## Reference-only (not build dependencies)

These projects are consulted for wire-level cross-checking only. Their code is
**not** copied into this repository.

| Project | Status | Use |
|---|---|---|
| `github.com/gomaja/go-asn1` | no stable tag | SGP.22/SGP.32 ASN.1 proofreading |
| `github.com/openiotrsp/openiotrsp` | young project | Software eUICC / BSP cross-check |
| `github.com/damonto/euicc-go` | low activity | LPA/eUICC message model cross-check |
| `github.com/CursedHardware/gsma-sgp22-asn1` | no declared license | `.asn` schema proofreading |
| SGP.26 test certificate distribution | test credentials | Certificates and UPP test fixtures |
| LPA reference implementations | mixed/REUSE | Manual end-to-end testing |
