// Command verify exercises the HTTP remediation path against the real router
// ONCE, in forced DRY_RUN mode: it logs in, reads the current LAN page,
// scrapes the sessionKey, parses the current LAN fields, and builds the save
// URL — then logs that URL (sessionKey and password redacted) WITHOUT sending
// it. Nothing on the router is changed.
//
// This is a developer/verification entrypoint, separate from the main
// watchdog loop, because the DHCP detector only runs on Linux; this command
// uses only the cross-platform HTTP path so it can be run on a Mac to confirm
// the scraping and save-URL construction against the real router before ever
// enabling real writes.
//
// Usage (run in your own terminal so the password never leaves your shell):
//
//	ROUTER_PASSWORD='your-router-password' go run ./cmd/verify
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

	logger.Printf("router=%s desired_dns=%s (DRY_RUN forced ON — nothing will be changed)",
		cfg.RouterURL, cfg.DesiredDNS)

	const forceDryRun = true
	if err := remediator.Restore(
		logger,
		cfg.RouterURL,
		remediator.Credentials{Password: cfg.RouterPassword},
		cfg.DesiredDNS,
		forceDryRun,
	); err != nil {
		logger.Fatalf("dry-run restore failed: %v", err)
	}

	logger.Printf("dry-run verify completed — inspect the constructed save URL logged above")
}
