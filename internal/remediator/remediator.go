// Package remediator restores the router's LAN DNS configuration by driving
// a real Chrome/Chromium browser via chromedp.
//
// Why a real browser (and not raw HTTP): this was tried exhaustively first
// (plaintext POST login, cookie jar, browser-like headers, exact form
// fields observed in the router's JS) and it never authenticates — GET
// /te_red_local.asp after the POST still returns the login page. Replaying
// the same request as an XHR from inside a real browser also fails
// identically. Only a genuine top-level browser navigation + native form
// submit (a real .click() on the login button) authenticates against this
// router. See engram topic dns-modem-watchdog/remediation-approach for the
// full investigation.
//
// Flow (confirmed manually against the real router):
//
//  1. Navigate to routerURL ("/"). The admin UI is a FRAMESET.
//  2. In the login child frame, set input[name=Password] and click the
//     submit button (value "Entrar"). The native submit authenticates.
//  3. Navigate to routerURL + "/te_red_local.asp". In the LAN child frame,
//     read (and, unless dryRun, set) input[name=DNSserver1] /
//     input[name=DNSserver2], then click "Aplicar cambios" to save.
//
// All element access happens via chromedp.Evaluate running JS that walks
// window.frames itself (see script.go) — chromedp's selector-based actions
// cannot reliably target elements inside child frames on this router, since
// frame targets are resolved by URL/title and this frameset's child frames
// are same-origin but otherwise unremarkable.
//
// Safety: Restore only ever writes when the current DNS configuration has
// actually drifted from the desired value — a no-drift call is a read-only
// no-op regardless of dryRun. On top of that, dryRun reads and logs the
// current DNS values and what WOULD be set on drift, and returns WITHOUT
// changing anything on the router — no login-page bypass, no button click on
// the LAN page. This is the intended way to verify the flow (does it reach
// the LAN page? are the field names right?) before ever setting
// DRY_RUN=false.
//
// See newBrowserContext (browser.go) for how the browser process itself is
// launched, including the CHROME_PATH and HEADFUL env overrides.
package remediator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/chromedp"
)

// Credentials holds the router login credentials.
type Credentials struct {
	// Password is the router admin password. Never logged by this package.
	Password string
}

// overallTimeout bounds the entire browser flow (launch, login, navigate,
// read/write DNS fields) so a hung browser or router can't block forever.
const overallTimeout = 60 * time.Second

// postActionSettle is how long Restore waits after an action that triggers
// browser-side navigation or JS handling (login submit, apply click) before
// reading the result, since these are driven by the page's own JS rather
// than a request Restore can wait on directly.
const postActionSettle = 3 * time.Second

// postNavigateSettle is the shorter wait after a plain top-level navigation,
// before the LAN page's frames are queried.
const postNavigateSettle = 2 * time.Second

// RestoreResult reports what Restore observed and did on the router's LAN
// page.
type RestoreResult struct {
	// Authenticated reports whether the browser login succeeded and reached
	// the LAN page. When false, DNSServer1/DNSServer2/Drifted/Applied are
	// zero values and Restore also returns a non-nil error.
	Authenticated bool
	// DNSServer1 and DNSServer2 are the DNS values currently configured on
	// the router's LAN page, as read BEFORE any write.
	DNSServer1 string
	DNSServer2 string
	// Drifted is true when the current DNS configuration (either field)
	// differs from desiredDNS.
	Drifted bool
	// Applied is true only when Restore actually wrote desiredDNS to the
	// router and clicked "Aplicar cambios". It is always false when Drifted
	// is false (nothing to do) and always false when dryRun is true (even
	// if drifted).
	Applied bool
}

// Restore logs into the router via a real browser, reads the current LAN DNS
// configuration, and — ONLY if it has actually drifted from desiredDNS —
// updates it.
//
// Restore never writes when the current configuration already matches
// desiredDNS: this keeps repeated calls (e.g. from a polling loop) idempotent
// and avoids needless router writes.
//
// When dryRun is true, Restore performs every step through reading the
// current DNS values on the LAN page, logs what WOULD be set if drift is
// detected, and returns WITHOUT touching the DNSserver1/DNSserver2 fields or
// clicking "Aplicar cambios". This is the intended way to verify the flow
// against the real router before ever setting dryRun to false.
//
// logger may be nil, in which case log.Default() is used.
func Restore(logger *log.Logger, routerURL string, creds Credentials, desiredDNS string, dryRun bool) (RestoreResult, error) {
	if logger == nil {
		logger = log.Default()
	}
	debug := loginDebug()

	ctx, cancel := newBrowserContext(context.Background())
	defer cancel()

	ctx, cancelTimeout := context.WithTimeout(ctx, overallTimeout)
	defer cancelTimeout()

	if err := chromedp.Run(ctx, chromedp.Navigate(routerURL+"/")); err != nil {
		return RestoreResult{}, fmt.Errorf("remediator: failed to navigate to router: %w", err)
	}
	if debug {
		logger.Printf("DEBUG_LOGIN: navigated to %s/", routerURL)
	}

	if err := loginViaBrowser(ctx, routerURL, creds.Password, debug, logger); err != nil {
		return RestoreResult{}, err
	}

	lan, err := readLANPage(ctx, routerURL, debug, logger)
	if err != nil {
		return RestoreResult{}, err
	}
	if !lan.Authenticated {
		return RestoreResult{}, fmt.Errorf("remediator: browser login did not reach the LAN page")
	}

	logger.Printf("current DNS: DNSserver1=%s DNSserver2=%s", lan.DNSServer1, lan.DNSServer2)

	result := RestoreResult{
		Authenticated: true,
		DNSServer1:    lan.DNSServer1,
		DNSServer2:    lan.DNSServer2,
		Drifted:       lan.DNSServer1 != desiredDNS || lan.DNSServer2 != desiredDNS,
	}

	if !result.Drifted {
		logger.Printf("DNS already correct (%s) — nothing to do", desiredDNS)
		return result, nil
	}

	if dryRun {
		logger.Printf("DRY_RUN: drift detected (current %s/%s) — would set %s",
			lan.DNSServer1, lan.DNSServer2, desiredDNS)
		return result, nil
	}

	if err := applyDNS(ctx, desiredDNS, debug, logger); err != nil {
		return result, err
	}

	logger.Printf("DNS updated: DNSserver1=%s DNSserver2=%s (apply clicked)", desiredDNS, desiredDNS)
	result.Applied = true
	return result, nil
}

// loginViaBrowser sets the password in the login frame and clicks the submit
// button, then waits for the router's own JS/navigation to settle.
func loginViaBrowser(ctx context.Context, routerURL, password string, debug bool, logger *log.Logger) error {
	passwordLiteral, err := jsStringLiteral(password)
	if err != nil {
		return fmt.Errorf("remediator: failed to encode password: %w", err)
	}
	script := fmt.Sprintf(loginScriptTemplate, passwordLiteral)

	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &result)); err != nil {
		return fmt.Errorf("remediator: login script failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("remediator: login form not found or not clickable: %s", result)
	}
	if debug {
		logger.Printf("DEBUG_LOGIN: login submit clicked")
	}

	if err := chromedp.Run(ctx, chromedp.Sleep(postActionSettle)); err != nil {
		return fmt.Errorf("remediator: post-login settle failed: %w", err)
	}
	return nil
}

// readLANPage navigates to the LAN configuration page and reads the current
// DNS values via JS (see script.go).
func readLANPage(ctx context.Context, routerURL string, debug bool, logger *log.Logger) (lanPageValues, error) {
	lanURL := routerURL + lanPagePath
	if err := chromedp.Run(ctx, chromedp.Navigate(lanURL)); err != nil {
		return lanPageValues{}, fmt.Errorf("remediator: failed to navigate to %s: %w", lanPagePath, err)
	}
	if err := chromedp.Run(ctx, chromedp.Sleep(postNavigateSettle)); err != nil {
		return lanPageValues{}, fmt.Errorf("remediator: LAN page settle failed: %w", err)
	}

	var raw string
	if err := chromedp.Run(ctx, chromedp.Evaluate(readLANScriptTemplate, &raw)); err != nil {
		return lanPageValues{}, fmt.Errorf("remediator: LAN page read script failed: %w", err)
	}
	if debug {
		logger.Printf("DEBUG_LOGIN: LAN page values=%s", raw)
	}

	var lan lanPageValues
	if err := json.Unmarshal([]byte(raw), &lan); err != nil {
		return lanPageValues{}, fmt.Errorf("remediator: failed to parse LAN page values: %w", err)
	}
	return lan, nil
}

// applyDNS sets DNSserver1/DNSserver2 to desiredDNS and clicks "Aplicar
// cambios" to save, then waits for the router to process the save.
func applyDNS(ctx context.Context, desiredDNS string, debug bool, logger *log.Logger) error {
	dnsLiteral, err := jsStringLiteral(desiredDNS)
	if err != nil {
		return fmt.Errorf("remediator: failed to encode desired DNS: %w", err)
	}
	script := fmt.Sprintf(setDNSScriptTemplate, dnsLiteral, dnsLiteral)

	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &result)); err != nil {
		return fmt.Errorf("remediator: set-DNS script failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("remediator: failed to set/apply DNS fields: %s", result)
	}
	if debug {
		logger.Printf("DEBUG_LOGIN: apply cambios clicked")
	}

	if err := chromedp.Run(ctx, chromedp.Sleep(postActionSettle)); err != nil {
		return fmt.Errorf("remediator: post-apply settle failed: %w", err)
	}
	return nil
}

// lanPagePath is the router's LAN configuration page.
const lanPagePath = "/te_red_local.asp"
