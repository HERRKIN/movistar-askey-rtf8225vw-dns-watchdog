package remediator

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildSaveURL(t *testing.T) {
	fields := LANFields{
		EthIPAddress:  "192.168.1.1",
		EthSubnetMask: "255.255.255.0",
		EnableDHCPSrv: "1",
		DHCPEthStart:  "192.168.1.81",
		DHCPEthEnd:    "192.168.1.219",
		LANHostDNS:    "192.168.1.254",
		LANHostDHCP:   "1",
		LoginSupport:  "1",
	}

	got := BuildSaveURL("http://192.168.1.1", fields, "abc123")

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("BuildSaveURL() produced an unparseable URL: %v", err)
	}

	if parsed.Scheme != "http" || parsed.Host != "192.168.1.1" {
		t.Errorf("BuildSaveURL() base = %s://%s, want http://192.168.1.1", parsed.Scheme, parsed.Host)
	}
	if parsed.Path != saveEndpointPath {
		t.Errorf("BuildSaveURL() path = %q, want %q", parsed.Path, saveEndpointPath)
	}

	q := parsed.Query()
	wantParams := map[string]string{
		"ethIpAddress":  "192.168.1.1",
		"ethSubnetMask": "255.255.255.0",
		"enblDhcpSrv":   "1",
		"dhcpEthStart":  "192.168.1.81",
		"dhcpEthEnd":    "192.168.1.219",
		"lanHostDns":    "192.168.1.254",
		"lanHostDhcp":   "1",
		"sessionKey":    "abc123",
		"loginSupport":  "1",
	}
	for key, want := range wantParams {
		if got := q.Get(key); got != want {
			t.Errorf("BuildSaveURL() param %q = %q, want %q", key, got, want)
		}
	}
}

func TestBuildSaveURL_TrimsTrailingSlashHandling(t *testing.T) {
	fields := LANFields{LANHostDNS: "192.168.1.254"}
	got := BuildSaveURL("http://192.168.1.1", fields, "key")

	want := "http://192.168.1.1" + saveEndpointPath
	if len(got) < len(want) || got[:len(want)] != want {
		t.Errorf("BuildSaveURL() = %q, want prefix %q", got, want)
	}
}

func TestBuildSaveURL_SessionKeyIsLast(t *testing.T) {
	fields := LANFields{
		EthIPAddress:  "192.168.1.1",
		EthSubnetMask: "255.255.255.0",
		EnableDHCPSrv: "1",
		DHCPEthStart:  "192.168.1.81",
		DHCPEthEnd:    "192.168.1.219",
		LANHostDNS:    "192.168.1.254,192.168.1.254",
		LANHostDHCP:   "1",
		LoginSupport:  "",
	}

	got := BuildSaveURL("http://192.168.1.1", fields, "abc123")

	if !strings.HasSuffix(got, "sessionKey=abc123") {
		t.Errorf("BuildSaveURL() = %q, want sessionKey as the last query parameter", got)
	}
}

func TestEncodeLanHostDns(t *testing.T) {
	got := encodeLanHostDns("192.168.1.254", "192.168.1.254")
	want := "192.168.1.254,192.168.1.254"
	if got != want {
		t.Errorf("encodeLanHostDns() = %q, want %q", got, want)
	}
}

func TestScrapeSessionKey(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		want    string
		wantErr bool
	}{
		{
			name: "double-quoted assignment",
			html: `<script>var sessionKey = "abc123";</script>`,
			want: "abc123",
		},
		{
			name: "single-quoted assignment",
			html: `<script>var sessionKey = 'xyz789';</script>`,
			want: "xyz789",
		},
		{
			name: "colon form as in JSON-like blob",
			html: `{"sessionKey": "tok-42"}`,
			want: "tok-42",
		},
		{
			name:    "no sessionKey present",
			html:    `<html><body>no token here</body></html>`,
			wantErr: true,
		},
		{
			name:    "empty html",
			html:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ScrapeSessionKey(tt.html)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ScrapeSessionKey() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ScrapeSessionKey() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ScrapeSessionKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "redacts sessionKey",
			in:   "http://192.168.1.1/cgi-bin/te_red_local.cgi?lanHostDns=1.1.1.1&sessionKey=abc123",
			want: "http://192.168.1.1/cgi-bin/te_red_local.cgi?lanHostDns=1.1.1.1&sessionKey=<redacted>",
		},
		{
			name: "redacts loginPassword",
			in:   "http://192.168.1.1/cgi-bin/te_acceso_router.cgi?loginPassword=hunter2&curWebPage=/x",
			want: "http://192.168.1.1/cgi-bin/te_acceso_router.cgi?loginPassword=<redacted>&curWebPage=/x",
		},
		{
			name: "no secrets present is a no-op",
			in:   "http://192.168.1.1/te_red_local.asp",
			want: "http://192.168.1.1/te_red_local.asp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactURL(tt.in)
			if got != tt.want {
				t.Errorf("redactURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
