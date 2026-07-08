package remediator

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// LANFields holds the LAN configuration parameters sent to the router's save
// endpoint. All fields are router-specific query parameter values; see
// engram topic dns-modem-watchdog/http-remediation for their origin.
type LANFields struct {
	EthIPAddress  string // ethIpAddress
	EthSubnetMask string // ethSubnetMask
	EnableDHCPSrv string // enblDhcpSrv
	DHCPEthStart  string // dhcpEthStart
	DHCPEthEnd    string // dhcpEthEnd
	LANHostDNS    string // lanHostDns — the desired DNS value goes here
	LANHostDHCP   string // lanHostDhcp
	LoginSupport  string // loginSupport
}

// BuildSaveURL constructs the GET URL for the router's LAN-save CGI
// endpoint, embedding the LAN fields and a fresh sessionKey.
//
// This is a pure function: given the same inputs it always produces the
// same URL, which makes it fully unit-testable without any network access.
//
// Parameter order in the resulting query string is fixed and sessionKey is
// placed LAST, per the captured spec (engram dns-modem-watchdog/login-spec)
// — some routers of this family validate that sessionKey trails the rest of
// the params, so this does not use url.Values.Encode() (which would sort
// keys alphabetically and break that ordering).
func BuildSaveURL(base string, fields LANFields, sessionKey string) string {
	ordered := []struct{ key, value string }{
		{"ethIpAddress", fields.EthIPAddress},
		{"ethSubnetMask", fields.EthSubnetMask},
		{"enblDhcpSrv", fields.EnableDHCPSrv},
		{"dhcpEthStart", fields.DHCPEthStart},
		{"dhcpEthEnd", fields.DHCPEthEnd},
		{"lanHostDns", fields.LANHostDNS},
		{"lanHostDhcp", fields.LANHostDHCP},
		{"loginSupport", fields.LoginSupport},
		{"sessionKey", sessionKey}, // MUST be last
	}

	parts := make([]string, 0, len(ordered))
	for _, kv := range ordered {
		parts = append(parts, url.QueryEscape(kv.key)+"="+url.QueryEscape(kv.value))
	}

	return fmt.Sprintf("%s%s?%s", base, saveEndpointPath, strings.Join(parts, "&"))
}

// encodeLanHostDns encodes the two DNS server addresses into the single
// lanHostDns query parameter value.
//
// HYPOTHESIS — UNVERIFIED against the live router: a comma-joined string
// literal was observed near the save-URL builder in the router's JS, and
// only a single "lanHostDns" parameter name was ever seen (never a
// repeated parameter). Best guess: lanHostDns=<dns1>,<dns2>.
//
// The alternative — a repeated `lanHostDns=` query parameter, one value per
// server — has NOT been ruled out. This is deliberately isolated in its own
// function so that if DRY_RUN verification against the real router shows
// this hypothesis is wrong, only this function needs to change; call sites
// are unaffected.
func encodeLanHostDns(dns1, dns2 string) string {
	return dns1 + "," + dns2
}

// sessionKeyPattern matches the sessionKey token embedded in the router's
// te_red_local.asp HTML page. The router embeds it as a JS variable, e.g.:
//
//	var sessionKey = "abc123";
//
// The exact surrounding markup is a guess based on the Askey CGI pattern
// documented in engram topic dns-modem-watchdog/http-remediation, and MUST
// be verified/adjusted against the real captured HTML if it doesn't match.
var sessionKeyPattern = regexp.MustCompile(`sessionKey["']?\s*[:=]\s*["']([^"']+)["']`)

// ScrapeSessionKey extracts the rotating sessionKey token from the router's
// LAN configuration page HTML.
func ScrapeSessionKey(html string) (string, error) {
	matches := sessionKeyPattern.FindStringSubmatch(html)
	if len(matches) < 2 {
		return "", fmt.Errorf("remediator: sessionKey not found in HTML")
	}
	return matches[1], nil
}

// sessionKeyInURLPattern and loginPasswordInURLPattern redact sensitive
// query parameter values from URLs before logging.
var (
	sessionKeyInURLPattern    = regexp.MustCompile(`(sessionKey=)[^&]*`)
	loginPasswordInURLPattern = regexp.MustCompile(`(loginPassword=)[^&]*`)
)

// redactURL returns a copy of rawURL with the sessionKey and loginPassword
// query parameter values (if present) replaced by "<redacted>", safe for
// logging. BuildSaveURL's output never contains loginPassword today, but
// this redacts it defensively in case future call sites log a different
// URL that does.
func redactURL(rawURL string) string {
	redacted := sessionKeyInURLPattern.ReplaceAllString(rawURL, "${1}<redacted>")
	redacted = loginPasswordInURLPattern.ReplaceAllString(redacted, "${1}<redacted>")
	return redacted
}
