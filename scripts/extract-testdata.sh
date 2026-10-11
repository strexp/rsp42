#!/usr/bin/env bash
#
# extract-testdata.sh - populate testdata/ from caller-provided sources.
#
# Sources are given explicitly (a local path or an http(s) URL to a directory,
# a .zip or a .tar.gz/.tgz); nothing is hardcoded.
#
# Usage:
#   extract-testdata.sh --sgp26 <src> --upp <src>
#
#   --sgp26  SGP.26 distribution containing
#            "Valid Test Cases/Variant O/{CI,EUM,eUICC,SM-DP+,SM-DS}".
#   --upp    tree containing the TS.48 UPP templates (*.der), e.g. a directory,
#            a .zip or a .tar.gz.
#
# Example:
#   ./scripts/extract-testdata.sh \
#     --sgp26 https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2025/01/SGP.26_v3.0.2-2026_files_v2.zip \
#     --upp   /path/to/smdpp-data/upp
#
# The script is idempotent: previously generated output is removed first.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SGP26_SRC=""
UPP_SRC=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sgp26) SGP26_SRC="${2:-}"; shift 2 ;;
    --upp)   UPP_SRC="${2:-}";   shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "error: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
if [[ -z "$SGP26_SRC" || -z "$UPP_SRC" ]]; then
  echo "error: --sgp26 and --upp are required (see --help)" >&2
  exit 2
fi

OUT_CERTS="testdata/sgp26"
OUT_UPP="testdata/upp"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# A browser User-Agent is sent because some upstream hosts reject plain clients.
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# fetch_tree <src> <workdir>: return a directory with the source tree contents.
fetch_tree() {
  local src="$1" work="$2"
  if [[ -d "$src" ]]; then
    echo "$src"
    return
  fi
  local file="$src"
  if [[ "$src" =~ ^https?:// ]]; then
    file="$work/download"
    mkdir -p "$work"
    echo ">> downloading $src" >&2
    curl -fsSL -A "$UA" -o "$file" "$src"
  fi
  mkdir -p "$work/out"
  case "$src" in
    *.zip)                unzip -q "$file" -d "$work/out" ;;
    *.tar.gz|*.tgz|*.tar) tar -xf "$file" -C "$work/out" ;;
    *) echo "error: unsupported source '$src' (need a directory, .zip or .tar.gz)" >&2; exit 1 ;;
  esac
  echo "$work/out"
}

# --- SGP.26 certificates ----------------------------------------------------
SGP26_TREE="$(fetch_tree "$SGP26_SRC" "$TMP/sgp26")"
SRC_VC="$(find "$SGP26_TREE" -type d -path '*Valid Test Cases/Variant O' | head -1)"
if [[ -z "$SRC_VC" ]]; then
  echo "error: could not find 'Valid Test Cases/Variant O' in $SGP26_SRC" >&2
  exit 1
fi

echo ">> extracting SGP.26 Variant O valid test certificates"
rm -rf "$OUT_CERTS"
mkdir -p "$OUT_CERTS"/{CertificateIssuer,EUM,eUICC,"SM-DP+"/{DPauth,DPpb,DPtls},"SM-DS"/{DSauth,DStls}}

copy() { # copy <src-relative> <dst-relative>
  local src="$SRC_VC/$1" dst="$OUT_CERTS/$2"
  if [[ ! -f "$src" ]]; then
    echo "   warning: missing $1" >&2
    return 0
  fi
  cp -a "$src" "$dst"
}

der2pem() { # der2pem <der-relative-name-in-out>
  local der="$OUT_CERTS/$1" pem="${1%.der}.pem"
  if [[ ! -f "$der" ]]; then
    echo "   warning: missing $1 for PEM conversion" >&2
    return 0
  fi
  openssl x509 -inform DER -in "$der" -out "$OUT_CERTS/$pem"
  rm -f "$der"
}

for curve in NIST BRP; do
  # Certificate Issuer (holds the CI private key used to sign test chains).
  copy "CI/CERT_CI_SIG_${curve}.der"  "CertificateIssuer/CERT_CI_${curve}.der"
  copy "CI/CERT_CI_SIG_${curve}.pem"  "CertificateIssuer/CERT_CI_${curve}.pem"
  copy "CI/SK_CI_SIG_${curve}.pem"    "CertificateIssuer/SK_CI_${curve}.pem"
  # EUM
  copy "EUM/CERT_EUM_SIG_${curve}.der" "EUM/CERT_EUM_${curve}.der"
  copy "EUM/SK_EUM_SIG_${curve}.pem"   "EUM/SK_EUM_${curve}.pem"
  # eUICC
  copy "eUICC/CERT_EUICC_SIG_${curve}.der" "eUICC/CERT_EUICC_${curve}.der"
  copy "eUICC/SK_EUICC_SIG_${curve}.pem"   "eUICC/SK_EUICC_${curve}.pem"
  # SM-DP+ signing + TLS
  copy "SM-DP+/SM_DPauth/CERT_S_SM_DPauth_VARO_SIG_${curve}.der" "SM-DP+/DPauth/CERT_DPauth_${curve}.der"
  copy "SM-DP+/SM_DPauth/SK_S_SM_DPauth_SIG_${curve}.pem"        "SM-DP+/DPauth/SK_DPauth_${curve}.pem"
  copy "SM-DP+/SM_DPpb/CERT_S_SM_DPpb_VARO_SIG_${curve}.der"     "SM-DP+/DPpb/CERT_DPpb_${curve}.der"
  copy "SM-DP+/SM_DPpb/SK_S_SM_DPpb_SIG_${curve}.pem"            "SM-DP+/DPpb/SK_DPpb_${curve}.pem"
  copy "SM-DP+/SM_DPtls/CERT_S_SM_DP_VARO_TLS_${curve}.der"      "SM-DP+/DPtls/CERT_DPtls_${curve}.der"
  copy "SM-DP+/SM_DPtls/SK_S_SM_DP_TLS_${curve}.pem"             "SM-DP+/DPtls/SK_DPtls_${curve}.pem"
  # SM-DS signing + TLS
  copy "SM-DS/SM_DSauth/CERT_S_SM_DSauth_VARO_SIG_${curve}.der" "SM-DS/DSauth/CERT_DSauth_${curve}.der"
  copy "SM-DS/SM_DSauth/SK_S_SM_DSauth_SIG_${curve}.pem"        "SM-DS/DSauth/SK_DSauth_${curve}.pem"
  copy "SM-DS/SM_DStls/CERT_S_SM_DS_VARO_TLS_${curve}.der"      "SM-DS/DStls/CERT_DStls_${curve}.der"
  copy "SM-DS/SM_DStls/SK_S_SM_DS_TLS_${curve}.pem"             "SM-DS/DStls/SK_DStls_${curve}.pem"
done

# Secondary SM-DP+/SM-DS identities (used for certificate-selection tests).
copy "SM-DP+/SM_DPauth/CERT_S_SM_DP2auth_VARO_SIG_NIST.der" "SM-DP+/DPauth/CERT_DP2auth_NIST.der"
copy "SM-DP+/SM_DPauth/SK_S_SM_DP2auth_SIG_NIST.pem"        "SM-DP+/DPauth/SK_DP2auth_NIST.pem"
copy "SM-DP+/SM_DPpb/CERT_S_SM_DP2pb_VARO_SIG_NIST.der"     "SM-DP+/DPpb/CERT_DP2pb_NIST.der"
copy "SM-DP+/SM_DPpb/SK_S_SM_DP2pb_SIG_NIST.pem"            "SM-DP+/DPpb/SK_DP2pb_NIST.pem"
copy "SM-DP+/SM_DPtls/CERT_S_SM_DP2_VARO_TLS_NIST.der"      "SM-DP+/DPtls/CERT_DP2tls_NIST.der"
copy "SM-DP+/SM_DPtls/SK_S_SM_DP2_TLS_NIST.pem"             "SM-DP+/DPtls/SK_DP2tls_NIST.pem"
copy "SM-DS/SM_DStls/CERT_S_SM_DS2_VARO_TLS_NIST.der"       "SM-DS/DStls/CERT_DS2tls_NIST.der"
copy "SM-DS/SM_DStls/SK_S_SM_DS2_TLS_NIST.pem"              "SM-DS/DStls/SK_DS2tls_NIST.pem"

# TLS certificates are consumed as PEM.
for f in "SM-DP+/DPtls/CERT_DPtls_NIST.der" "SM-DP+/DPtls/CERT_DPtls_BRP.der" \
         "SM-DP+/DPtls/CERT_DP2tls_NIST.der" \
         "SM-DS/DStls/CERT_DStls_NIST.der" "SM-DS/DStls/CERT_DStls_BRP.der" \
         "SM-DS/DStls/CERT_DS2tls_NIST.der"; do
  der2pem "$f"
done

# --- TS.48 UPP templates ----------------------------------------------------
UPP_TREE="$(fetch_tree "$UPP_SRC" "$TMP/upp")"
UPP_DIR="$(find "$UPP_TREE" -type d -path '*smdpp-data/upp' | head -1)"
if [[ -z "$UPP_DIR" ]]; then
  UPP_DIR="$(dirname "$(find "$UPP_TREE" -name 'TS48*.der' -print -quit)")"
fi
if [[ -z "$UPP_DIR" || "$UPP_DIR" == "." ]]; then
  echo "error: no TS.48 UPP templates (*.der) found in $UPP_SRC" >&2
  exit 1
fi
echo ">> copying TS.48 UPP templates"
rm -rf "$OUT_UPP"
mkdir -p "$OUT_UPP"
find "$UPP_DIR" -maxdepth 1 -name '*.der' -exec cp -a {} "$OUT_UPP/" \;

echo ">> done"
echo "   certificates: $OUT_CERTS"
echo "   UPP templates: $OUT_UPP"
