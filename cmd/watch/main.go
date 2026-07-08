// Command watch is a browser-only DNS watchdog loop: it does NOT probe DHCP
// (that detector only runs on Linux), so it works on macOS. Instead it drives
// the router's admin UI directly via remediator.Restore on every tick, which
// itself reads the router's current LAN DNS configuration and only writes
// when that configuration has actually drifted from DESIRED_DNS.
//
// This is the auto-fixing entrypoint for a developer machine (e.g. running
// overnight on a Mac): unlike cmd/verify, it runs in REAL mode by default
// (dryRun=false) — remediator.Restore's own drift check is the safety net
// that keeps it from writing when nothing is wrong.
//
// Usage (run in your own terminal so the password never leaves your shell):
//
//	ROUTER_PASSWORD='your-router-password' DESIRED_DNS='192.168.1.254' \
//	  NTFY_URL='https://ntfy.sh' NTFY_TOPIC='your-topic' \
//	  go run ./cmd/watch
//
// Set CHECK_INTERVAL (default 10m), ROUTER_URL (default
// http://192.168.1.1), EVENT_LOG_PATH (default /data/events.jsonl — override
// to a writable local path on macOS, e.g. EVENT_LOG_PATH=./events.jsonl),
// HEADFUL=1 to watch the browser while it runs, and CHROME_PATH if chromedp
// can't find your Chrome/Chromium binary automatically.
package main

import (
	"log"
	"os"
	"time"

	"dns-modem-watchdog/internal/config"
	"dns-modem-watchdog/internal/eventlog"
	"dns-modem-watchdog/internal/notify"
	"dns-modem-watchdog/internal/remediator"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmsgprefix)
	logger.SetPrefix("dns-watch: ")

	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("config error: %v", err)
	}

	notifier := notify.New(cfg.NtfyURL, cfg.NtfyTopic, cfg.NtfyToken)
	events := eventlog.New(cfg.EventLogPath)

	logger.Printf("starting browser-only watchdog: desired_dns=%s interval=%s router=%s event_log=%s",
		cfg.DesiredDNS, cfg.CheckInterval, cfg.RouterURL, cfg.EventLogPath)
	logger.Printf("real mode: remediator.Restore writes ONLY when the router's LAN page has actually drifted from desired_dns")

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	// Run an initial cycle immediately, then on every tick.
	runCycle(logger, cfg, notifier, events)
	for range ticker.C {
		runCycle(logger, cfg, notifier, events)
	}
}

// runCycle performs one browser-driven read -> (maybe) restore -> log/notify
// cycle against the router.
func runCycle(logger *log.Logger, cfg config.Config, notifier *notify.Notifier, events *eventlog.Logger) {
	res, err := remediator.Restore(logger, cfg.RouterURL, remediator.Credentials{Password: cfg.RouterPassword}, cfg.DesiredDNS, false)

	if err != nil {
		logger.Printf("error: %v", err)
		if logErr := events.Append(eventlog.Event{
			Type:   eventlog.EventError,
			Detail: err.Error(),
		}); logErr != nil {
			logger.Printf("failed to write event log: %v", logErr)
		}
		if notifyErr := notifier.Send("DNS watchdog error", err.Error()); notifyErr != nil {
			logger.Printf("notification failed: %v", notifyErr)
		}
		return
	}

	observed := []string{res.DNSServer1, res.DNSServer2}

	switch {
	case res.Drifted && res.Applied:
		logger.Printf("drift-fixed: was %v, restored to %s", observed, cfg.DesiredDNS)
		if logErr := events.Append(eventlog.Event{
			Type:        eventlog.EventRestore,
			ObservedDNS: observed,
			DesiredDNS:  cfg.DesiredDNS,
		}); logErr != nil {
			logger.Printf("failed to write event log: %v", logErr)
		}
		body := "advertised/config DNS had drifted to " + observed[0] + "/" + observed[1] +
			"; restored to " + cfg.DesiredDNS + "."
		if notifyErr := notifier.Send("DNS drift restored", body); notifyErr != nil {
			logger.Printf("notification failed: %v", notifyErr)
		}
	default:
		// Not drifted (or drifted-but-not-applied, which can't happen here
		// since dryRun is always false): plain OK, no notification.
		logger.Printf("ok: DNS matches desired (%s)", cfg.DesiredDNS)
		if logErr := events.Append(eventlog.Event{
			Type:        eventlog.EventOK,
			ObservedDNS: observed,
			DesiredDNS:  cfg.DesiredDNS,
		}); logErr != nil {
			logger.Printf("failed to write event log: %v", logErr)
		}
	}
}
