package remediator

import (
	"fmt"
	"regexp"
	"strings"
)

// LANPageFields holds the CURRENT LAN configuration values as read from the
// router's /te_red_local.asp page. These must be preserved as-is (except
// DNS) when building the save request, so the DHCP range / gateway aren't
// accidentally reset.
type LANPageFields struct {
	GatewayIPAddress string // gatewayIPaddress
	GatewayNetmask   string // gatewayNetmask
	DHCPActive       string // DHCPActive
	StartIPAddress   string // startIPAddress
	EndIPAddress     string // endIPAddress
	DNSServer1       string // DNSserver1
	DNSServer2       string // DNSserver2
}

// lanPageFieldNames lists the LAN page field names in the order they should
// be reported when missing.
var lanPageFieldNames = [...]string{
	"gatewayIPaddress", "gatewayNetmask", "DHCPActive",
	"startIPAddress", "endIPAddress", "DNSserver1", "DNSserver2",
}

// ParseLANFields extracts the CURRENT LAN configuration values from the
// router's te_red_local.asp HTML, so the save request preserves every field
// except DNS.
//
// This is a pure function over the HTML string. The exact router markup has
// not been captured verbatim, so this parser tolerates the two most common
// shapes for router admin forms:
//
//  1. <input name="X" ... value="Y" ...> (or value before name)
//  2. <select name="X">...<option value="Y" ... selected ...></select>
//     (DHCPActive is documented elsewhere — engram dns-modem-watchdog/context
//     — as rendered via a <select>)
//
// MUST be verified/adjusted against the real captured HTML.
func ParseLANFields(html string) (LANPageFields, error) {
	var out LANPageFields
	var missing []string

	extract := func(name string) string {
		v, ok := extractFieldValue(html, name)
		if !ok {
			missing = append(missing, name)
		}
		return v
	}

	out.GatewayIPAddress = extract(lanPageFieldNames[0])
	out.GatewayNetmask = extract(lanPageFieldNames[1])
	out.DHCPActive = extract(lanPageFieldNames[2])
	out.StartIPAddress = extract(lanPageFieldNames[3])
	out.EndIPAddress = extract(lanPageFieldNames[4])
	out.DNSServer1 = extract(lanPageFieldNames[5])
	out.DNSServer2 = extract(lanPageFieldNames[6])

	if len(missing) > 0 {
		return out, fmt.Errorf("remediator: LAN page missing fields: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// extractFieldValue looks up a form field's current value in raw HTML,
// tolerant of attribute order and both the <input value=...> and
// <select><option selected> shapes. Each regex is bounded to a single tag
// (or a single <select>...</select> block) by disallowing '<'/'>' between
// attributes, so it won't accidentally span multiple elements.
func extractFieldValue(html, name string) (string, bool) {
	quoted := regexp.QuoteMeta(name)

	nameThenValue := regexp.MustCompile(`(?is)<[^<>]*\bname=["']` + quoted + `["'][^<>]*\bvalue=["']([^"']*)["'][^<>]*>`)
	if m := nameThenValue.FindStringSubmatch(html); len(m) == 2 {
		return m[1], true
	}

	valueThenName := regexp.MustCompile(`(?is)<[^<>]*\bvalue=["']([^"']*)["'][^<>]*\bname=["']` + quoted + `["'][^<>]*>`)
	if m := valueThenName.FindStringSubmatch(html); len(m) == 2 {
		return m[1], true
	}

	selectBlock := regexp.MustCompile(`(?is)<select\b[^<>]*\bname=["']` + quoted + `["'][^<>]*>(.*?)</select>`)
	if sm := selectBlock.FindStringSubmatch(html); len(sm) == 2 {
		inner := sm[1]

		optValueThenSelected := regexp.MustCompile(`(?is)<option\b[^<>]*\bvalue=["']([^"']*)["'][^<>]*\bselected\b[^<>]*>`)
		if om := optValueThenSelected.FindStringSubmatch(inner); len(om) == 2 {
			return om[1], true
		}

		optSelectedThenValue := regexp.MustCompile(`(?is)<option\b[^<>]*\bselected\b[^<>]*\bvalue=["']([^"']*)["'][^<>]*>`)
		if om := optSelectedThenValue.FindStringSubmatch(inner); len(om) == 2 {
			return om[1], true
		}
	}

	return "", false
}

// buildLANFieldsForRestore maps the CURRENT LAN page fields plus the
// desired DNS into the LANFields needed by BuildSaveURL, preserving every
// value except DNS.
//
// Two fields have NO confirmed source on te_red_local.asp and are
// best-effort assumptions pending live verification:
//
//   - LANHostDHCP ("lanHostDhcp"): no matching field was identified on the
//     LAN page. We mirror DHCPActive's current value, since both names
//     suggest "is DHCP serving the LAN enabled". If this is wrong, a save
//     request could unintentionally disable/enable the DHCP server.
//   - LoginSupport ("loginSupport"): expected value on this save call is
//     unknown. Defaults to empty string until verified.
func buildLANFieldsForRestore(current LANPageFields, desiredDNS string) LANFields {
	return LANFields{
		EthIPAddress:  current.GatewayIPAddress,
		EthSubnetMask: current.GatewayNetmask,
		EnableDHCPSrv: current.DHCPActive,
		DHCPEthStart:  current.StartIPAddress,
		DHCPEthEnd:    current.EndIPAddress,
		LANHostDNS:    encodeLanHostDns(desiredDNS, desiredDNS),
		LANHostDHCP:   current.DHCPActive, // ASSUMPTION — unverified, see doc comment above
		LoginSupport:  "",                 // ASSUMPTION — unverified, see doc comment above
	}
}
