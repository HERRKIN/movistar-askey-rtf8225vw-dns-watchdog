package config

import (
	"os"
	"testing"
	"time"
)

// clearEnv unsets all config-related env vars so tests start from a clean slate.
func clearEnv(t *testing.T) {
	t.Helper()
	vars := []string{
		"ROUTER_URL", "ROUTER_PASSWORD", "DESIRED_DNS", "CHECK_INTERVAL",
		"NTFY_URL", "NTFY_TOPIC", "EVENT_LOG_PATH", "IFACE", "DRY_RUN",
	}
	for _, v := range vars {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTER_PASSWORD", "secret")
	t.Setenv("DESIRED_DNS", "192.168.1.254")
	t.Setenv("NTFY_URL", "https://ntfy.example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.RouterURL != defaultRouterURL {
		t.Errorf("RouterURL = %q, want %q", cfg.RouterURL, defaultRouterURL)
	}
	if cfg.CheckInterval != defaultCheckInterval {
		t.Errorf("CheckInterval = %v, want %v", cfg.CheckInterval, defaultCheckInterval)
	}
	if cfg.NtfyTopic != defaultNtfyTopic {
		t.Errorf("NtfyTopic = %q, want %q", cfg.NtfyTopic, defaultNtfyTopic)
	}
	if cfg.EventLogPath != defaultEventLogPath {
		t.Errorf("EventLogPath = %q, want %q", cfg.EventLogPath, defaultEventLogPath)
	}
	if cfg.RouterPassword != "secret" {
		t.Errorf("RouterPassword = %q, want %q", cfg.RouterPassword, "secret")
	}
	if !cfg.DryRun {
		t.Errorf("DryRun = %v, want true (safe default)", cfg.DryRun)
	}
}

func TestLoad_MissingPassword(t *testing.T) {
	clearEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with no ROUTER_PASSWORD should return an error, got nil")
	}
}

func TestLoad_MissingDesiredDNS(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTER_PASSWORD", "secret")
	t.Setenv("NTFY_URL", "https://ntfy.example.com")

	if _, err := Load(); err == nil {
		t.Fatal("Load() with no DESIRED_DNS should return an error, got nil")
	}
}

func TestLoad_MissingNtfyURL(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTER_PASSWORD", "secret")
	t.Setenv("DESIRED_DNS", "192.168.1.254")

	if _, err := Load(); err == nil {
		t.Fatal("Load() with no NTFY_URL should return an error, got nil")
	}
}

func TestLoad_CustomValues(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTER_PASSWORD", "secret")
	t.Setenv("ROUTER_URL", "http://10.0.0.1")
	t.Setenv("DESIRED_DNS", "10.0.0.254")
	t.Setenv("CHECK_INTERVAL", "5m")
	t.Setenv("NTFY_URL", "https://ntfy.example.com")
	t.Setenv("NTFY_TOPIC", "custom-topic")
	t.Setenv("EVENT_LOG_PATH", "/tmp/events.jsonl")
	t.Setenv("IFACE", "eth0")
	t.Setenv("DRY_RUN", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.RouterURL != "http://10.0.0.1" {
		t.Errorf("RouterURL = %q, want %q", cfg.RouterURL, "http://10.0.0.1")
	}
	if cfg.DesiredDNS != "10.0.0.254" {
		t.Errorf("DesiredDNS = %q, want %q", cfg.DesiredDNS, "10.0.0.254")
	}
	if cfg.CheckInterval != 5*time.Minute {
		t.Errorf("CheckInterval = %v, want %v", cfg.CheckInterval, 5*time.Minute)
	}
	if cfg.Iface != "eth0" {
		t.Errorf("Iface = %q, want %q", cfg.Iface, "eth0")
	}
	if cfg.DryRun {
		t.Errorf("DryRun = %v, want false (explicitly disabled)", cfg.DryRun)
	}
}

func TestLoad_InvalidCheckInterval(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTER_PASSWORD", "secret")
	t.Setenv("CHECK_INTERVAL", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with invalid CHECK_INTERVAL should return an error, got nil")
	}
}

func TestLoad_InvalidDryRun(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTER_PASSWORD", "secret")
	t.Setenv("DRY_RUN", "not-a-bool")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with invalid DRY_RUN should return an error, got nil")
	}
}

func TestLoad_DryRunAcceptsCommonBooleanSpellings(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"1", true},
		{"0", false},
		{"true", true},
		{"false", false},
		{"TRUE", true},
		{"FALSE", false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("ROUTER_PASSWORD", "secret")
			t.Setenv("DESIRED_DNS", "192.168.1.254")
			t.Setenv("NTFY_URL", "https://ntfy.example.com")
			t.Setenv("DRY_RUN", tt.raw)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if cfg.DryRun != tt.want {
				t.Errorf("DryRun = %v, want %v", cfg.DryRun, tt.want)
			}
		})
	}
}
