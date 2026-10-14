# Multi-stage build: compile the static rsp42 binary, then run it on Alpine with
# the dn42 root CA preinstalled for outbound *.dn42 TLS.

FROM golang:latest AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/rsp42 ./cmd/rsp42

FROM alpine:latest
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
