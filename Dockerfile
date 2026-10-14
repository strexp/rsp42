# Multi-stage build: compile the static rsp42 binary, then run it on Alpine with
# the dn42 root CA preinstalled for outbound *.dn42 TLS.
#
# The base images are pinned to the Go minor in go.mod (1.27) and to a specific
# Alpine release, so a moving :latest tag cannot silently change the toolchain or
# the runtime libc. They stay overridable as build args for a deliberate bump:
#   docker build --build-arg GO_IMAGE=golang:1.28-bookworm .

ARG GO_IMAGE=golang:1.27-bookworm
ARG RUNTIME_IMAGE=alpine:3.22

FROM ${GO_IMAGE} AS build

# Build metadata for `rsp42 version`. It is passed in because .dockerignore
# excludes .git, so the Makefile's git-derived defaults are unavailable here.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Same entry point as a local build, so the image binary and `make build` cannot
# diverge in flags or version metadata.
RUN CGO_ENABLED=0 make build BIN_DIR=/out VERSION="${VERSION}" COMMIT="${COMMIT}" DATE="${DATE}"

FROM ${RUNTIME_IMAGE}
RUN apk add --no-cache ca-certificates
# Vendored dn42 root CA (CC0); see docs/operations.md.
COPY deploy/dn42-root-ca.crt /usr/local/share/ca-certificates/dn42-root-ca.crt
RUN update-ca-certificates

COPY --from=build /out/rsp42 /usr/local/bin/rsp42
COPY config/config.example.yaml /etc/rsp42/config.example.yaml

EXPOSE 8443 8444 9000 9443 9444 9100

# The role is selected at run time; there is no default role. Set
#   -e RSP42_ROLE=smdpp   (SM-DP+)
#   -e RSP42_ROLE=smds    (SM-DS)
ENV RSP42_CONFIG=/etc/rsp42/config.yaml
ENTRYPOINT ["/usr/local/bin/rsp42"]
CMD ["sh", "-c", "exec rsp42 \"${RSP42_ROLE:?set RSP42_ROLE=smdpp or smds}\" --config \"$RSP42_CONFIG\""]
