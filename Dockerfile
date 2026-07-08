# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO disabled + linux/amd64-friendly static binary. -s -w strip debug info.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/dns-modem-watchdog .

# --- final stage ---
# NOTE: NOT a distroless/static image anymore, and NOT small. The remediator
# now drives a real Chrome/Chromium browser via chromedp (raw HTTP login was
# confirmed exhaustively NOT to work against this router — see the package
# doc on internal/remediator), so the final image MUST include a real
# browser binary. This trades a materially larger image (Chromium adds a few
# hundred MB) for correctness: the browser only actually launches for the
# few seconds a remediation takes (on drift), so the runtime cost is bounded
# even though the image size is not. If image size becomes a real problem
# later, revisit (slimmer Chromium build, browser in a sidecar, etc.) — but
# do not compromise on "must actually authenticate" to save image size.
#
# Also intentionally running as root (not a distroless "nonroot" image): the
# active DHCP probe needs a raw socket (CAP_NET_RAW). Linux capabilities
# granted via `cap_add` are reliably applied to a root-UID process; granting
# them to a non-root UID additionally requires ambient capability
# propagation that is not guaranteed across all container runtimes.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/dns-modem-watchdog /dns-modem-watchdog

# The active DHCP probe needs raw sockets (CAP_NET_RAW) and host networking
# to talk directly to the LAN — see docker-compose.yml and README.md. The
# remediator needs Chromium (installed above); chromedp finds it on PATH
# automatically — set CHROME_PATH to override.
ENTRYPOINT ["/dns-modem-watchdog"]
