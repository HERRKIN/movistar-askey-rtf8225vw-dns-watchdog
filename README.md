# dns-modem-watchdog

A tiny, single-purpose watchdog that guards the LAN DNS configuration of a
Movistar (Askey RTF8225VW) router. The router is remotely managed by the ISP
over TR-069/CWMP and periodically re-provisions itself back to ISP-default
DNS, silently bypassing a local Pi-hole. This watchdog detects that drift,
restores the desired DNS, logs every event (to measure how often it
happens), and notifies via [ntfy](https://ntfy.sh).

## Two-tier design

1. **Detector (cheap, runs every tick)** — sends an active DHCP DISCOVER on
   the LAN and reads DHCP option 6 (Domain Name Server) from the OFFER. This
   measures the real symptom: what DNS server is actually being handed out
   to clients, regardless of what the router's admin UI claims. No browser,
   no login required for this path.
2. **Remediator (on-demand, only runs when drift is detected)** — drives a
   real Chrome/Chromium browser via
   [chromedp](https://github.com/chromedp/chromedp): navigates to the router
   admin UI, logs in, navigates to `/te_red_local.asp`, and updates the
   `DNSserver1`/`DNSserver2` fields before clicking "Aplicar cambios".

Every check cycle appends a structured event (`ok` | `drift` | `restore` |
`error`) to an append-only JSONL log, and an ntfy notification is sent
whenever drift is detected and (attempted to be) restored.

## Why a real browser (not raw HTTP)

An earlier version of this watchdog scripted the router's login purely over
`net/http` (plaintext POST, cookie jar, browser-like headers, the exact form
fields observed in the router's own JS). That was confirmed, exhaustively,
to NOT work against this router: the POST returns 200, but a subsequent GET
of `/te_red_local.asp` still returns the login page — the session never
actually authenticates. Replaying the identical request as an XHR from
inside a real browser fails the same way. Only a genuine top-level browser
navigation with a native form submit (a real `.click()` on the login button)
authenticates. This appears to be a real quirk/bug of this router family,
not a bug in the request construction.

Because of that, `internal/remediator` now drives an actual browser via
chromedp instead of raw HTTP. This is slower and heavier (needs a real
Chrome/Chromium binary — see Deploying below) but it is the only approach
confirmed to work.

## Status: implemented, behind a DRY_RUN safety gate

The login + read + set DNS + apply flow is implemented in
`internal/remediator` via chromedp. Because it depends on an actual browser
authenticating against the real router's JS/DOM, it is **not** covered by
fake-server unit tests the way the old HTTP flow was — it needs to be
verified live (see `cmd/verify` below) with `DRY_RUN=true` before ever
setting `DRY_RUN=false`.

- **`DRY_RUN=true` is the default.** In dry-run mode, `Restore` logs in via
  the browser, navigates to the LAN page, and reads the current
  `DNSserver1`/`DNSserver2` values, then **logs** what it found and what it
  WOULD set — WITHOUT touching those fields or clicking "Aplicar cambios".
  Run the watchdog in dry-run first, trigger a drift (or just watch the
  periodic log lines), and confirm the logged values look correct before
  setting `DRY_RUN=false`.
- **Plaintext password.** The router's login form takes the password in
  plain text (confirmed — no client-side hashing). This is inherent to the
  router, not something this watchdog can change; it's only acceptable
  because the browser only ever talks to the router over the LAN. Treat
  `ROUTER_PASSWORD` as a secret everywhere else (env vars, logs, Coolify
  secrets) regardless — and note the password is never written to any log
  line produced by this package, even with `DEBUG_LOGIN=1`.

## Configuration

All configuration is via environment variables (see `env.example`):

| Variable | Default | Required | Notes |
|---|---|---|---|
| `ROUTER_URL` | `http://192.168.1.1` | no | Router admin base URL |
| `ROUTER_PASSWORD` | — | **yes** | Router admin password (secret) |
| `DESIRED_DNS` | `192.168.1.254` | no | Your Pi-hole / desired DNS address |
| `CHECK_INTERVAL` | `10m` | no | Go duration format |
| `NTFY_URL` | `https://ntfy.example.com` | no | Self-hosted ntfy server |
| `NTFY_TOPIC` | `dns-watchdog` | no | ntfy topic |
| `EVENT_LOG_PATH` | `/data/events.jsonl` | no | Append-only JSONL event log |
| `IFACE` | auto-detected | no | Network interface for the DHCP probe |
| `DRY_RUN` | `true` | no | Safety gate — see "Status" above. Set to `false` only after verifying a dry-run log line |
| `CHROME_PATH` | auto-detected | no | Path to a Chrome/Chromium binary, if chromedp can't find one automatically |
| `HEADFUL` | `""` (headless) | no | Set to `1` to run the browser with a visible window, for local debugging |
| `DEBUG_LOGIN` | `""` (off) | no | Set to any non-empty value for verbose remediator step logging (never logs the password) |

> Note: due to sandbox restrictions in the environment that generated this
> scaffold, the example file is committed as `env.example` instead of the
> conventional `.env.example` (writing any `.env*` path was denied by the
> tool's permission system). Copy it to `.env` before running:
> `cp env.example .env`.

## Running locally

```sh
go build ./...
go test ./...
```

The active DHCP probe (`internal/detector.Probe`) only builds on `linux`
(see `internal/detector/probe_linux.go`) because it needs a raw socket via
`github.com/insomniacslk/dhcp`'s `nclient4` client, which requires
`CAP_NET_RAW`. On other platforms (e.g. macOS during development),
`internal/detector/probe_other.go` provides a stub that returns a clear
"not supported on this OS" error, so the rest of the codebase — including
all the deterministic, unit-tested logic — still builds and tests cleanly
everywhere.

`go build ./...` and `go test ./...` do NOT need a browser installed —
`internal/remediator`'s chromedp-driven code compiles and is exercised only
at runtime (`go vet`/`go build` type-check it like any other Go code; there
are no unit tests that actually launch a browser). To actually exercise the
remediation flow, see `cmd/verify` below, which does need a real Chrome or
Chromium on the machine running it.

### Live-verifying the remediation flow (`cmd/verify`)

`cmd/verify` drives the real browser flow against the real router, in
FORCED `DRY_RUN` mode — it can read the current DNS values but can never
change them. Run it from your own terminal so the router password never
leaves your shell:

```sh
ROUTER_PASSWORD='your-router-password' go run ./cmd/verify
```

Useful variations:

```sh
# Watch the browser window while it runs, for debugging:
HEADFUL=1 ROUTER_PASSWORD='...' go run ./cmd/verify

# Verbose step-by-step logging (never logs the password):
DEBUG_LOGIN=1 ROUTER_PASSWORD='...' go run ./cmd/verify

# Point at a specific Chrome/Chromium binary if auto-detection fails:
CHROME_PATH=/path/to/chrome ROUTER_PASSWORD='...' go run ./cmd/verify
```

A successful run logs the current `DNSserver1`/`DNSserver2` values read from
the router. If you don't have `DESIRED_DNS`/`NTFY_URL` set already,
`config.Load` still requires `DESIRED_DNS`; `cmd/verify` supplies a
harmless placeholder `NTFY_URL` automatically.

## Deploying on Coolify

Build and run via the provided `Dockerfile` / `docker-compose.yml`:

```sh
cp env.example .env   # fill in ROUTER_PASSWORD at minimum
docker compose up -d --build
```

Two things are **required** for the DHCP probe to work in production:

- `network_mode: host` — the container needs to see LAN broadcast traffic
  directly; the default bridge network can't provide that.
- `cap_add: [NET_RAW]` — the probe opens a raw socket to send/receive DHCP
  packets.

The final image is built from `debian:bookworm-slim` with `chromium`
installed — **not** a distroless/static image anymore. The remediator drives
a real browser via chromedp (see "Why a real browser" above), so the image
must include one; this is a deliberate size-for-correctness tradeoff (the
image grows by a few hundred MB). The browser only actually launches for the
few seconds a remediation takes (i.e. only when drift is detected), so the
extra size doesn't cost extra runtime resources most of the time.

The image also still runs as root (not a `nonroot` user) — deliberately,
because Linux capability propagation to a non-root UID via `cap_add` is not
guaranteed across all container runtimes, while a root-UID process reliably
receives exactly the capability set Docker grants it (here, only
`NET_RAW`).

In Coolify: deploy from this repo, set the service's Docker Compose method
(or equivalent host-network + capability settings if using the App/Docker
Image deployment type), and set `ROUTER_PASSWORD` as a secret.

## Testing

- Runner: `go test ./...` (cross-platform — macOS and Linux; only
  `internal/detector`'s real `Probe` is Linux-only, see above).
- Unit-tested (pure, deterministic logic): DHCP option-6 parsing
  (`ParseDNSServers`), DNS drift comparison (`HasDrifted`), DNS list
  dedup (`DedupIPs`), network interface selection (`PickInterface`), config
  loading/validation, event log appends (using `t.TempDir()`), and the ntfy
  notifier (using `httptest.Server`).
- `internal/remediator` has NO unit tests of the browser-driven flow itself:
  it depends on a real Chrome/Chromium binary launching and interacting with
  the real router's live JS/DOM (frame layout, exact field names, submit
  button behavior), none of which is meaningfully fakeable in a fast,
  deterministic unit test — a fake HTML page can't reproduce "does a real
  browser's native form submit authenticate against this specific router".
  `go build ./...` / `go vet ./...` still fully type-check the package. It
  is instead verified live via `cmd/verify` (see above), in forced
  `DRY_RUN` mode.
- NOT unit-tested (needs the real router/LAN, or a real Linux host):
  the active DHCP probe (`Probe`, linux-only) and the entire browser-driven
  remediation flow (login, LAN page navigation, reading/setting DNS fields)
  — verify both live with `DRY_RUN=true` before ever setting `DRY_RUN=false`.
