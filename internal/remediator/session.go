package remediator

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// Login authenticates against the router admin UI via a plaintext POST to
// te_acceso_router.cgi, and returns an *http.Client whose cookie jar holds
// the resulting session cookie for use in subsequent requests.
//
// Confirmed (engram dns-modem-watchdog/login-spec): no hashing — the
// password is sent as plain text over LAN HTTP. loginUsername is always the
// fixed literal "user", even though the UI only prompts for a password.
func Login(routerURL string, creds Credentials) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("remediator: failed to create cookie jar: %w", err)
	}
	client := &http.Client{Jar: jar, Timeout: defaultHTTPTimeout}

	form := url.Values{}
	form.Set("curWebPage", lanPagePath)
	form.Set("loginUsername", fixedLoginUsername)
	form.Set("loginPassword", creds.Password)

	req, err := http.NewRequest(http.MethodPost, routerURL+loginPath, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("remediator: failed to build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remediator: login request failed: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return nil, fmt.Errorf("remediator: failed to read login response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remediator: login returned status %d", resp.StatusCode)
	}

	reqURL, err := url.Parse(routerURL)
	if err != nil {
		return nil, fmt.Errorf("remediator: invalid router URL %q: %w", routerURL, err)
	}
	if len(jar.Cookies(reqURL)) == 0 {
		return nil, fmt.Errorf("remediator: login did not return a session cookie — check ROUTER_PASSWORD")
	}

	return client, nil
}

// fetchLANPage fetches the router's LAN configuration page using an
// authenticated client (from Login) and returns its raw HTML body.
func fetchLANPage(client *http.Client, routerURL string) (string, error) {
	resp, err := client.Get(routerURL + lanPagePath)
	if err != nil {
		return "", fmt.Errorf("remediator: failed to fetch %s: %w", lanPagePath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("remediator: failed to read %s response: %w", lanPagePath, err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("remediator: %s returned status %d", lanPagePath, resp.StatusCode)
	}

	return string(body), nil
}
