// Package remediator restores the router's LAN DNS configuration via the
// router's plain-HTTP admin CGI endpoints (no browser required).
//
// Flow (confirmed against the router's own JS/HTML — see engram topics
// dns-modem-watchdog/http-remediation and dns-modem-watchdog/login-spec):
//
//  1. POST /cgi-bin/te_acceso_router.cgi to log in (plaintext password,
//     fixed username "user"). The response sets a session cookie.
//     (session.go)
//  2. GET /te_red_local.asp (with the session cookie) to scrape a fresh
//     sessionKey and read the CURRENT LAN configuration. (session.go,
//     saveurl.go, lanfields.go)
//  3. GET /cgi-bin/te_red_local.cgi (with the session cookie) with every
//     current LAN field preserved except the DNS, plus the sessionKey.
//     (saveurl.go, lanfields.go)
//  4. GET /cgi-bin/te_logout.cgi to close the session (best-effort).
//     (remediator.go)
//
// This package uses only net/http + net/http/cookiejar (both stdlib), so it
// builds and runs identically on macOS and Linux — unlike the DHCP probe in
// internal/detector, which is Linux-only. That means the whole HTTP
// remediation path can be exercised against a fake HTTP server on a Mac.
//
// Safety: Restore has a DRY_RUN mode (see the dryRun parameter) that
// performs every step up to and including building the save URL, logs it
// (with sessionKey and any password redacted), and returns WITHOUT ever
// sending the request that would actually change the router's config. This
// is the intended way to verify the constructed request against the real
// router before ever flipping DRY_RUN off.
//
// Open assumptions that still need live verification against the real
// router — see doc comments on encodeLanHostDns (saveurl.go) and
// buildLANFieldsForRestore (lanfields.go), and the engram apply-progress
// entry for this change.
//
// File layout (single package, split by responsibility):
//   - remediator.go — this file: shared endpoints/consts, Credentials,
//     Restore (top-level orchestration), logout.
//   - session.go — Login and fetchLANPage (HTTP session concerns).
//   - saveurl.go — LANFields, BuildSaveURL, encodeLanHostDns,
//     ScrapeSessionKey, redactURL (save-request construction + logging
//     safety).
//   - lanfields.go — LANPageFields, ParseLANFields, buildLANFieldsForRestore
//     (reading and preserving the router's current LAN config).
package remediator

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Router endpoints and fixed login parameters, per engram topics
// dns-modem-watchdog/http-remediation and dns-modem-watchdog/login-spec.
const (
	loginPath        = "/cgi-bin/te_acceso_router.cgi"
	lanPagePath      = "/te_red_local.asp"
	saveEndpointPath = "/cgi-bin/te_red_local.cgi"
	logoutPath       = "/cgi-bin/te_logout.cgi"

	// fixedLoginUsername is always "user", even though the router's login
	// UI only prompts for a password.
	fixedLoginUsername = "user"

	defaultHTTPTimeout = 15 * time.Second
)

// Credentials holds the router login credentials.
type Credentials struct {
	// Password is the router admin password, sent in PLAIN TEXT over LAN
	// HTTP (confirmed: no md5/sha/base64 hashing on this router). Treat it
	// as a secret in every other layer (env vars, logs) even though the
	// wire protocol itself doesn't protect it.
	Password string
}

// logout closes the router session, best-effort. Failures are logged but
// never fail the caller — a lingering session isn't worth failing a
// successful (or dry-run) restore over.
func logout(logger *log.Logger, client *http.Client, routerURL string) {
	resp, err := client.Get(routerURL + logoutPath)
	if err != nil {
		logger.Printf("remediator: logout request failed (non-fatal): %v", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

// Restore logs into the router, reads its current LAN configuration, and
// updates only the DNS to desiredDNS — preserving every other LAN field.
//
// When dryRun is true, Restore performs every step through building the
// save URL, logs it (sessionKey and any password redacted) via logger, and
// returns nil WITHOUT ever sending the request that would change the
// router's configuration. This is the intended way to verify the
// constructed request against the real router before ever setting dryRun
// to false. When dryRun is false, the save request is actually sent.
//
// A best-effort logout is always attempted before returning (whether or not
// dryRun is set), to avoid leaving a dangling authenticated session.
//
// logger may be nil, in which case log.Default() is used.
func Restore(logger *log.Logger, routerURL string, creds Credentials, desiredDNS string, dryRun bool) error {
	if logger == nil {
		logger = log.Default()
	}

	client, err := Login(routerURL, creds)
	if err != nil {
		return fmt.Errorf("remediator: restore failed: %w", err)
	}
	defer logout(logger, client, routerURL)

	html, err := fetchLANPage(client, routerURL)
	if err != nil {
		return fmt.Errorf("remediator: restore failed: %w", err)
	}

	sessionKey, err := ScrapeSessionKey(html)
	if err != nil {
		return fmt.Errorf("remediator: restore failed: %w", err)
	}

	current, err := ParseLANFields(html)
	if err != nil {
		return fmt.Errorf("remediator: restore failed: %w", err)
	}

	fields := buildLANFieldsForRestore(current, desiredDNS)
	saveURL := BuildSaveURL(routerURL, fields, sessionKey)

	if dryRun {
		logger.Printf("DRY_RUN: would send save request: %s", redactURL(saveURL))
		return nil
	}

	resp, err := client.Get(saveURL)
	if err != nil {
		return fmt.Errorf("remediator: save request failed: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("remediator: failed to read save response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("remediator: save request returned status %d", resp.StatusCode)
	}

	logger.Printf("save request sent: %s", redactURL(saveURL))
	return nil
}
