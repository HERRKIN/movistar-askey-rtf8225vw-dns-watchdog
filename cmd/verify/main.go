// Command verify exercises the browser-driven remediation path against the
// real router ONCE, in forced DRY_RUN mode: it launches a real Chrome/
// Chromium (via chromedp), logs in through the router's admin UI, navigates
// to the LAN configuration page, and reads the current DNSserver1/
// DNSserver2 values — then logs what it found and what it WOULD set, WITHOUT
// ever touching the DNS fields or clicking "Aplicar cambios". Nothing on the
// router is changed.
//
// This is a developer/verification entrypoint, separate from the main
// watchdog loop, because the DHCP detector only runs on Linux; this command
// uses only the browser-driven remediation path (which is cross-platform, as
// long as a Chrome/Chromium binary is available) so it can be run on a Mac
// to confirm the login + LAN page flow against the real router before ever
// enabling real writes.
//
// Usage (run in your own terminal so the password never leaves your shell):
//
//	ROUTER_PASSWORD='your-router-password' go run ./cmd/verify
//
// Set HEADFUL=1 to watch the browser while it runs, and CHROME_PATH if
// chromedp can't find your Chrome/Chromium binary automatically.
//
// DRY_RUN is forced on here regardless of the environment, so this can never
// change the router configuration.
package main

import (
	"log"
	"os"

	"dns-modem-watchdog/internal/config"
	"dns-modem-watchdog/internal/remediator"
)

func main() {
	logger := log.New(os.Stdout, "verify: ", log.LstdFlags|log.Lmsgprefix)

	// verify never sends notifications, but config.Load requires NTFY_URL.
	// Supply a harmless placeholder if unset so this tool only needs
	// ROUTER_PASSWORD and DESIRED_DNS.
	if os.Getenv("NTFY_URL") == "" {
		os.Setenv("NTFY_URL", "https://ntfy.invalid")
	}

	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("config error: %v", err)
	}

	// By default this is a DRY RUN. Set APPLY=1 to perform a REAL apply
	// (sets DNSserver1/2 to DESIRED_DNS and clicks "Aplicar cambios").
	dryRun := os.Getenv("APPLY") == ""
	if dryRun {
		logger.Printf("router=%s desired_dns=%s (DRY_RUN — nothing will be changed)",
			cfg.RouterURL, cfg.DesiredDNS)
	} else {
		logger.Printf("router=%s desired_dns=%s (APPLY=1 — will WRITE and click Aplicar cambios)",
			cfg.RouterURL, cfg.DesiredDNS)
	}

	if err := remediator.Restore(
		logger,
		cfg.RouterURL,
		remediator.Credentials{Password: cfg.RouterPassword},
		cfg.DesiredDNS,
		dryRun,
	); err != nil {
		logger.Fatalf("restore failed: %v", err)
	}

	logger.Printf("verify completed")
}
