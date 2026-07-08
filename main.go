// Command dns-modem-watchdog periodically probes the LAN via DHCP for the
// advertised DNS servers, and restores the desired DNS configuration on the
// router when it drifts from the expected value.
//
// See openspec/project.md for the full design rationale.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"dns-modem-watchdog/internal/config"
	"dns-modem-watchdog/internal/detector"
	"dns-modem-watchdog/internal/eventlog"
	"dns-modem-watchdog/internal/notify"
	"dns-modem-watchdog/internal/remediator"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmsgprefix)
	logger.SetPrefix("dns-modem-watchdog: ")

	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("config error: %v", err)
	}

	iface := cfg.Iface
	if iface == "" {
		iface, err = resolveDefaultInterface()
		if err != nil {
			logger.Fatalf("failed to resolve a network interface (set IFACE explicitly): %v", err)
		}
	}

	notifier := notify.New(cfg.NtfyURL, cfg.NtfyTopic, cfg.NtfyToken)
	events := eventlog.New(cfg.EventLogPath)

	logger.Printf("starting watchdog: iface=%s desired_dns=%s interval=%s router=%s dry_run=%v",
		iface, cfg.DesiredDNS, cfg.CheckInterval, cfg.RouterURL, cfg.DryRun)
	if cfg.DryRun {
		logger.Printf("DRY_RUN is enabled: remediation will be logged but NOT applied. Set DRY_RUN=false to allow real writes.")
	}

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	// Run an initial check immediately, then on every tick.
	runCheck(logger, cfg, iface, notifier, events)
	for range ticker.C {
		runCheck(logger, cfg, iface, notifier, events)
	}
}

// runCheck performs one detect -> (maybe) remediate -> log/notify cycle.
func runCheck(logger *log.Logger, cfg config.Config, iface string, notifier *notify.Notifier, events *eventlog.Logger) {
	advertised, err := detector.Probe(iface, detector.DefaultTimeout)
	if err != nil {
		logger.Printf("probe failed: %v", err)
		if logErr := events.Append(eventlog.Event{
			Type:   eventlog.EventError,
			Detail: err.Error(),
		}); logErr != nil {
			logger.Printf("failed to write event log: %v", logErr)
		}
		return
	}

	drifted, err := detector.HasDrifted(advertised, cfg.DesiredDNS)
	if err != nil {
		logger.Printf("drift comparison failed: %v", err)
		return
	}

	observed := ipsToStrings(advertised)

	if !drifted {
		logger.Printf("ok: advertised DNS matches desired (%s)", cfg.DesiredDNS)
		if err := events.Append(eventlog.Event{
			Type:        eventlog.EventOK,
			ObservedDNS: observed,
			DesiredDNS:  cfg.DesiredDNS,
		}); err != nil {
			logger.Printf("failed to write event log: %v", err)
		}
		return
	}

	logger.Printf("drift detected: advertised=%v desired=%s", observed, cfg.DesiredDNS)
	if err := events.Append(eventlog.Event{
		Type:        eventlog.EventDrift,
		ObservedDNS: observed,
		DesiredDNS:  cfg.DesiredDNS,
	}); err != nil {
		logger.Printf("failed to write event log: %v", err)
	}

	res, restoreErr := remediator.Restore(logger, cfg.RouterURL, remediator.Credentials{Password: cfg.RouterPassword}, cfg.DesiredDNS, cfg.DryRun)

	restoreEvent := eventlog.Event{
		Type:        eventlog.EventRestore,
		ObservedDNS: observed,
		DesiredDNS:  cfg.DesiredDNS,
	}
	notifyTitle := "DNS drift restored"
	notifyBody := "Advertised DNS drifted from " + cfg.DesiredDNS + " and was restored."

	switch {
	case restoreErr != nil:
		logger.Printf("remediation failed: %v", restoreErr)
		restoreEvent.Type = eventlog.EventError
		restoreEvent.Detail = restoreErr.Error()
		notifyTitle = "DNS drift detected — remediation FAILED"
		notifyBody = "Advertised DNS drifted from " + cfg.DesiredDNS + " and automatic remediation failed: " + restoreErr.Error()
	case !res.Drifted:
		// The DHCP-advertised value drifted, but the router's own LAN page
		// already shows the desired DNS (e.g. the router already
		// self-corrected, or DHCP lease info was briefly stale). Nothing was
		// written.
		logger.Printf("router DNS already correct (%s) — no write performed", cfg.DesiredDNS)
		restoreEvent.Type = eventlog.EventOK
		restoreEvent.Detail = "router LAN page already matched desired DNS; no write performed"
	case res.Applied:
		logger.Printf("DNS restored: DNSserver1=%s DNSserver2=%s -> %s", res.DNSServer1, res.DNSServer2, cfg.DesiredDNS)
		restoreEvent.Detail = fmt.Sprintf("restored from %s/%s to %s", res.DNSServer1, res.DNSServer2, cfg.DesiredDNS)
	default:
		// Drifted but not applied: dry-run mode.
		notifyTitle = "DNS drift detected (DRY_RUN — not restored)"
		notifyBody = "Advertised DNS drifted from " + cfg.DesiredDNS + ". DRY_RUN is enabled: the fix was NOT applied. See logs for the constructed save request."
		restoreEvent.Detail = "dry_run: fix not applied"
	}

	if err := events.Append(restoreEvent); err != nil {
		logger.Printf("failed to write event log: %v", err)
	}

	if err := notifier.Send(notifyTitle, notifyBody); err != nil {
		logger.Printf("notification failed: %v", err)
	}
}

// resolveDefaultInterface picks a usable network interface when IFACE is not
// set explicitly.
func resolveDefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	return detector.PickInterface(ifaces)
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
