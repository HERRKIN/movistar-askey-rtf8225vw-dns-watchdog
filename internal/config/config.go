// Package config loads and validates the watchdog's runtime configuration
// from environment variables.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// loadDotEnv best-effort loads KEY=VALUE lines from local env files into the
// process environment (without overriding variables already set). It is a
// local-development convenience; in production (e.g. Coolify) these files are
// absent and real environment variables take precedence.
//
// It reads ".env" (standard) and "watchdog.secrets" (an alternate name used
// for local testing in environments where .env access is restricted).
func loadDotEnv() {
	// watchdog.secrets is read first so it takes precedence over any stale
	// .env (e.g. one created from env.example with placeholder values).
	// Real process environment variables still win over both.
	for _, name := range []string{"watchdog.secrets", ".env"} {
		loadEnvFile(name)
	}
}

func loadEnvFile(name string) {
	f, err := os.Open(name)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}

// Config holds all runtime settings for the watchdog.
type Config struct {
	// RouterURL is the base URL of the router's admin UI (e.g. http://192.168.1.1).
	RouterURL string
	// RouterPassword is the router admin password. Secret — never log this value.
	RouterPassword string
	// DesiredDNS is the DNS server address the LAN should be advertising.
	// Required — set via the DESIRED_DNS env var (no default, so no
	// deployment's IPs are baked into the source).
	DesiredDNS string
	// CheckInterval is how often the detector probes the LAN via DHCP.
	CheckInterval time.Duration
	// NtfyURL is the base URL of the ntfy server used for notifications.
	// Required — set via the NTFY_URL env var (no default).
	NtfyURL string
	// NtfyTopic is the ntfy topic to publish notifications to.
	NtfyTopic string
	// NtfyToken is an optional ntfy access token sent as a Bearer token, for
	// servers that require authentication to publish. Empty = anonymous.
	NtfyToken string
	// EventLogPath is the path to the append-only JSONL event log.
	EventLogPath string
	// Iface is the network interface to use for the DHCP probe. Optional —
	// when empty, the detector picks a default interface.
	Iface string
	// DryRun, when true (the default), makes the remediator log the
	// constructed save request instead of sending it. This is a safety
	// gate — verify the constructed request against the real router in
	// dry-run mode before ever setting this to false.
	DryRun bool
}

const (
	defaultRouterURL     = "http://192.168.1.1"
	defaultCheckInterval = 10 * time.Minute
	defaultNtfyTopic     = "dns-watchdog"
	defaultEventLogPath  = "/data/events.jsonl"
)

// Load reads configuration from environment variables, applies defaults for
// optional fields, and validates required fields.
func Load() (Config, error) {
	loadDotEnv()

	cfg := Config{
		RouterURL:      getEnv("ROUTER_URL", defaultRouterURL),
		RouterPassword: os.Getenv("ROUTER_PASSWORD"),
		DesiredDNS:     os.Getenv("DESIRED_DNS"),
		NtfyURL:        os.Getenv("NTFY_URL"),
		NtfyTopic:      getEnv("NTFY_TOPIC", defaultNtfyTopic),
		NtfyToken:      os.Getenv("NTFY_TOKEN"),
		EventLogPath:   getEnv("EVENT_LOG_PATH", defaultEventLogPath),
		Iface:          os.Getenv("IFACE"),
	}

	interval := defaultCheckInterval
	if raw := os.Getenv("CHECK_INTERVAL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid CHECK_INTERVAL %q: %w", raw, err)
		}
		interval = parsed
	}
	cfg.CheckInterval = interval

	dryRun := true
	if raw := os.Getenv("DRY_RUN"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid DRY_RUN %q: %w", raw, err)
		}
		dryRun = parsed
	}
	cfg.DryRun = dryRun

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate checks that all required fields are present and well-formed.
func (c Config) Validate() error {
	if c.RouterPassword == "" {
		return fmt.Errorf("ROUTER_PASSWORD is required")
	}
	if c.RouterURL == "" {
		return fmt.Errorf("ROUTER_URL must not be empty")
	}
	if c.DesiredDNS == "" {
		return fmt.Errorf("DESIRED_DNS must not be empty")
	}
	if c.CheckInterval <= 0 {
		return fmt.Errorf("CHECK_INTERVAL must be a positive duration")
	}
	if c.NtfyURL == "" {
		return fmt.Errorf("NTFY_URL must not be empty")
	}
	if c.NtfyTopic == "" {
		return fmt.Errorf("NTFY_TOPIC must not be empty")
	}
	if c.EventLogPath == "" {
		return fmt.Errorf("EVENT_LOG_PATH must not be empty")
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
