# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.23-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO disabled + linux/amd64-friendly static binary. -s -w strip debug info
# to keep the binary (and final image) small.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/dns-modem-watchdog .

# --- final stage ---
# NOTE: intentionally NOT the ":nonroot" distroless variant. The active DHCP
# probe needs a raw socket (CAP_NET_RAW). Linux capabilities granted via
# `cap_add` are reliably applied to a root-UID process; granting them to a
# non-root UID additionally requires ambient capability propagation that is
# not guaranteed across all container runtimes. Running as root here (with
# only NET_RAW added, all other capabilities dropped by Docker's default
# profile) is the pragmatic tradeoff for a tiny, single-purpose LAN tool.
FROM gcr.io/distroless/static-debian12

COPY --from=build /out/dns-modem-watchdog /dns-modem-watchdog

# The active DHCP probe needs raw sockets (CAP_NET_RAW) and host networking
# to talk directly to the LAN — see docker-compose.yml and README.md.
ENTRYPOINT ["/dns-modem-watchdog"]
