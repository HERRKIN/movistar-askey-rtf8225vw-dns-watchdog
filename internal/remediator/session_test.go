package remediator

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLogin_Success(t *testing.T) {
	fr := newFakeRouter(t)

	client, err := Login(fr.server.URL, Credentials{Password: "secret"})
	if err != nil {
		t.Fatalf("Login() unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("Login() returned a nil client")
	}
	if fr.loginHits.Load() != 1 {
		t.Errorf("login endpoint hits = %d, want 1", fr.loginHits.Load())
	}

	// The returned client's cookie jar must carry the session cookie for
	// subsequent requests.
	u, _ := url.Parse(fr.server.URL)
	if len(client.Jar.Cookies(u)) == 0 {
		t.Error("Login() client has no cookies for the router URL")
	}
}

func TestLogin_RejectedByRouter(t *testing.T) {
	fr := newFakeRouter(t)
	fr.rejectLogin = true

	_, err := Login(fr.server.URL, Credentials{Password: "wrong"})
	if err == nil {
		t.Fatal("Login() expected error on non-2xx status, got nil")
	}
}

func TestLogin_NoCookieReturned(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 but no Set-Cookie
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	_, err := Login(server.URL, Credentials{Password: "secret"})
	if err == nil {
		t.Fatal("Login() expected error when no session cookie is returned, got nil")
	}
}
