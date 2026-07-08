package eventlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogger_Append_WritesOneJSONLinePerEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger := New(path)

	events := []Event{
		{Type: EventOK, ObservedDNS: []string{"192.168.1.254"}, DesiredDNS: "192.168.1.254"},
		{Type: EventDrift, ObservedDNS: []string{"200.28.4.130"}, DesiredDNS: "192.168.1.254", Detail: "advertised DNS does not match desired"},
		{Type: EventRestore, DesiredDNS: "192.168.1.254", Detail: "remediation applied"},
	}

	for _, e := range events {
		if err := logger.Append(e); err != nil {
			t.Fatalf("Append() unexpected error: %v", err)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open event log: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) != len(events) {
		t.Fatalf("got %d lines, want %d", len(lines), len(events))
	}

	for i, line := range lines {
		var got Event
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if got.Type != events[i].Type {
			t.Errorf("line %d: Type = %q, want %q", i, got.Type, events[i].Type)
		}
		if got.Timestamp.IsZero() {
			t.Errorf("line %d: Timestamp should be auto-filled, got zero value", i)
		}
	}
}

func TestLogger_Append_CreatesParentDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "sub", "events.jsonl")
	logger := New(path)

	if err := logger.Append(Event{Type: EventOK}); err != nil {
		t.Fatalf("Append() unexpected error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected event log file to exist: %v", err)
	}
}

func TestLogger_Append_PreservesExplicitTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger := New(path)

	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := logger.Append(Event{Type: EventError, Timestamp: ts}); err != nil {
		t.Fatalf("Append() unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read event log: %v", err)
	}

	var got Event
	if err := json.Unmarshal(data[:len(data)-1], &got); err != nil {
		t.Fatalf("failed to unmarshal event: %v", err)
	}
	if !got.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, ts)
	}
}
