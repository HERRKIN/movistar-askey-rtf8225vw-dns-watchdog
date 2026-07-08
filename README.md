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
2. **Remediator (on-demand, only runs when drift is detected)** — logs into
   the router admin UI over plain HTTP (`POST /cgi-bin/te_acceso_router.cgi`,
   plaintext password, cookie-based session), reads the CURRENT LAN
   configuration from `/te_red_local.asp` (scraping a fresh `sessionKey` and
   every other LAN field so they're preserved), and issues a single `GET
   /cgi-bin/te_red_local.cgi` that changes ONLY the DNS. No browser needed —
   the router's own "Aplicar cambios" button does a plain `location = <url>`
   GET, not an XHR/form submit, so this is fully scriptable with `net/http`.

Every check cycle appends a structured event (`ok` | `drift` | `restore` |
`error`) to an append-only JSONL log, and an ntfy notification is sent
whenever drift is detected and (attempted to be) restored.

## Status: implemented, behind a DRY_RUN safety gate

The full login + read + build + save + logout flow is implemented in
`internal/remediator` and cross-platform tested (macOS + Linux) against a
fake HTTP server — see Testing below. It has **not yet been exercised
against the real router**, so two things matter before ever pointing this at
production:

- **`DRY_RUN=true` is the default.** In dry-run mode, `Restore` logs in,
  reads the LAN page, and builds the save URL, then **logs it** (with
  `sessionKey` and any password redacted) and returns WITHOUT sending the
  request that would change the router's config. Run the watchdog in
  dry-run first, trigger a drift (or just watch the periodic log lines),
  and manually verify the logged URL looks correct before setting
  `DRY_RUN=false`.
- **Plaintext password over LAN HTTP.** The router's login endpoint accepts
  the password in plain text (confirmed — no md5/sha/base64 hashing). This
  is inherent to the router, not something this watchdog can change; it's
  only acceptable because the request never leaves the LAN. Treat
  `ROUTER_PASSWORD` as a secret everywhere else (env vars, logs, Coolify
  secrets) regardless.

### Open assumptions — need live verification

These are documented in code (see doc comments on `encodeLanHostDns` and
`buildLANFieldsForRestore` in `internal/remediator`) and must be confirmed
against a `DRY_RUN=true` log line before flipping `DRY_RUN=false`:

1. **`lanHostDns` encoding** — hypothesis: a single comma-joined value,
   `lanHostDns=<dns1>,<dns2>` (both set to `DESIRED_DNS`). The alternative —
   a repeated `lanHostDns=` query parameter, one per server — has not been
   ruled out. Isolated in `encodeLanHostDns()` so only that function needs
   to change if wrong.
2. **`lanHostDhcp`** — no confirmed source field on `te_red_local.asp`.
   Currently mirrors `DHCPActive`'s current value as a best-effort guess.
   If wrong, a save request could unintentionally toggle the DHCP server.
3. **`loginSupport`** — expected value on the save call is unknown.
   Currently defaults to an empty string.

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

The final image is built from `gcr.io/distroless/static-debian12` (root
user, not the `:nonroot` variant) — deliberately, because Linux capability
propagation to a non-root UID via `cap_add` is not guaranteed across all
container runtimes, while a root-UID process reliably receives exactly the
capability set Docker grants it (here, only `NET_RAW`).

In Coolify: deploy from this repo, set the service's Docker Compose method
(or equivalent host-network + capability settings if using the App/Docker
Image deployment type), and set `ROUTER_PASSWORD` as a secret.

## Testing

- Runner: `go test ./...` (cross-platform — macOS and Linux both fully
  exercise `internal/remediator`; only `internal/detector`'s real `Probe`
  is Linux-only, see above).
- Unit-tested (pure, deterministic logic): DHCP option-6 parsing
  (`ParseDNSServers`), DNS drift comparison (`HasDrifted`), DNS list
  dedup (`DedupIPs`), network interface selection (`PickInterface`), config
  loading/validation, event log appends (using `t.TempDir()`), and the ntfy
  notifier (using `httptest.Server`).
- `internal/remediator` (split by responsibility across
  `saveurl.go`/`lanfields.go`/`session.go`/`remediator.go`), fully unit- and
  integration-tested against a fake HTTP server (`httptest.Server`), no
  real router needed:
  - `BuildSaveURL`, `encodeLanHostDns`, `ScrapeSessionKey`, `redactURL`
    (`saveurl_test.go`)
  - `ParseLANFields`, `buildLANFieldsForRestore` (`lanfields_test.go`)
  - `Login` — success, rejected credentials, missing session cookie
    (`session_test.go`)
  - `Restore` end-to-end — dry-run does NOT hit the save endpoint but does
    log in/read/logout; a real run does hit the save endpoint; login
    failure and missing-LAN-fields errors propagate correctly
    (`remediator_test.go`, using the shared `fakeRouter` test double in
    `fakerouter_test.go`)
- NOT unit-tested (needs the real router/LAN): the active DHCP probe
  (`Probe`, linux-only) and whether the three open assumptions above
  (`lanHostDns` encoding, `lanHostDhcp`, `loginSupport`) are actually
  correct — verify those with `DRY_RUN=true` against the real router before
  ever setting `DRY_RUN=false`.
