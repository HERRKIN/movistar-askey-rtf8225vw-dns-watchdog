package notify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNotifier_Send(t *testing.T) {
	var gotMethod, gotPath, gotTitle, gotBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotTitle = r.Header.Get("Title")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New(server.URL, "dns-watchdog", "")
	if err := n.Send("DNS drift detected", "restored to 192.168.1.254"); err != nil {
		t.Fatalf("Send() unexpected error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/dns-watchdog" {
		t.Errorf("path = %q, want /dns-watchdog", gotPath)
	}
	if gotTitle != "DNS drift detected" {
		t.Errorf("Title header = %q, want %q", gotTitle, "DNS drift detected")
	}
	if gotBody != "restored to 192.168.1.254" {
		t.Errorf("body = %q, want %q", gotBody, "restored to 192.168.1.254")
	}
}

func TestNotifier_Send_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	n := New(server.URL, "dns-watchdog", "")
	if err := n.Send("title", "body"); err == nil {
		t.Fatal("Send() expected error on non-2xx status, got nil")
	}
}

func TestNew_TrimsTrailingSlash(t *testing.T) {
	n := New("https://ntfy.example.com/", "topic", "")
	if n.BaseURL != "https://ntfy.example.com" {
		t.Errorf("BaseURL = %q, want %q", n.BaseURL, "https://ntfy.example.com")
	}
}

func TestNotifier_Send_BearerToken(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New(server.URL, "dns-watchdog", "tk_test123")
	if err := n.Send("t", "b"); err != nil {
		t.Fatalf("Send() unexpected error: %v", err)
	}
	if gotAuth != "Bearer tk_test123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tk_test123")
	}
}
