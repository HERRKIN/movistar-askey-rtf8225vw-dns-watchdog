// Package eventlog appends structured drift/restore events to a JSONL file,
// used to measure how often the router's DNS configuration drifts.
package eventlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EventType identifies the kind of event recorded.
type EventType string

const (
	// EventDrift records that the advertised DNS differs from the desired DNS.
	EventDrift EventType = "drift"
	// EventRestore records that remediation was attempted to fix drift.
	EventRestore EventType = "restore"
	// EventOK records that the advertised DNS matched the desired DNS.
	EventOK EventType = "ok"
	// EventError records that a check or remediation attempt failed.
	EventError EventType = "error"
)

// Event is a single append-only log entry.
type Event struct {
	Timestamp   time.Time `json:"ts"`
	Type        EventType `json:"event"`
	ObservedDNS []string  `json:"observed_dns,omitempty"`
	DesiredDNS  string    `json:"desired_dns,omitempty"`
	Detail      string    `json:"detail,omitempty"`
}

// Logger appends events to a JSONL file at Path.
type Logger struct {
	Path string
}

// New creates a Logger writing to the given path.
func New(path string) *Logger {
	return &Logger{Path: path}
}

// Append serializes the event as one JSON line and appends it to the log
// file, creating the file (and parent directory) if it doesn't exist.
func (l *Logger) Append(e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	dir := filepath.Dir(l.Path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("eventlog: failed to create directory %s: %w", dir, err)
		}
	}

	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("eventlog: failed to open %s: %w", l.Path, err)
	}
	defer f.Close()

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("eventlog: failed to marshal event: %w", err)
	}

	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("eventlog: failed to write to %s: %w", l.Path, err)
	}

	return nil
}
