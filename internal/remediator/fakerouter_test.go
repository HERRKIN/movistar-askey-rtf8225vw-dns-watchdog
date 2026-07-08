package remediator

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// fakeRouter is a minimal httptest server that stands in for the real
// router so the full HTTP remediation path (login -> read -> build ->
// save/dry-run -> logout) can be exercised deterministically on any OS.
// Shared by session_test.go and remediator_test.go.
type fakeRouter struct {
	server         *httptest.Server
	loginHits      atomic.Int32
	lanPageHits    atomic.Int32
	saveHits       atomic.Int32
	logoutHits     atomic.Int32
	rejectLogin    bool
	lanPageHTML    string
	sawCookieOnLAN bool
}

func newFakeRouter(t *testing.T) *fakeRouter {
	t.Helper()
	fr := &fakeRouter{
		lanPageHTML: `<html><body>
			<script>var sessionKey = "fresh-session-key";</script>
			<input name="gatewayIPaddress" value="192.168.1.1">
			<input name="gatewayNetmask" value="255.255.255.0">
			<select name="DHCPActive"><option value="1" selected>Enabled</option></select>
			<input name="startIPAddress" value="192.168.1.81">
			<input name="endIPAddress" value="192.168.1.219">
			<input name="DNSserver1" value="200.28.4.130">
			<input name="DNSserver2" value="200.28.4.129">
		</body></html>`,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
		fr.loginHits.Add(1)
		if fr.rejectLogin {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-session-value", Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(lanPagePath, func(w http.ResponseWriter, r *http.Request) {
		fr.lanPageHits.Add(1)
		if c, err := r.Cookie("session"); err == nil && c.Value == "test-session-value" {
			fr.sawCookieOnLAN = true
		}
		fmt.Fprint(w, fr.lanPageHTML)
	})
	mux.HandleFunc(saveEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		fr.saveHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(logoutPath, func(w http.ResponseWriter, r *http.Request) {
		fr.logoutHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	fr.server = httptest.NewServer(mux)
	t.Cleanup(fr.server.Close)
	return fr
}
