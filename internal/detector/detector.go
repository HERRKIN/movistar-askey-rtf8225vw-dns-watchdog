// Package detector probes the LAN with an active DHCP DISCOVER and reports
// the DNS servers currently advertised via DHCP option 6.
//
// The active probe (Probe) requires CAP_NET_RAW and host networking, because
// it sends/receives raw DHCP broadcast traffic on the LAN interface. It is
// intentionally NOT covered by unit tests — it is verified behaviorally
// against the real router on the LAN (see openspec/project.md, Testing).
//
// Probe's real implementation (probe_linux.go) is built only on linux,
// since that is the only supported deployment target (Docker container with
// network_mode: host + CAP_NET_RAW; see Dockerfile/docker-compose.yml). A
// stub implementation (probe_other.go) is built on every other OS so this
// package — and its pure, unit-tested logic below — still builds and tests
// cleanly on a developer's machine (e.g. macOS).
//
// The deterministic pieces — parsing DHCP option 6 into a list of IPs,
// comparing an advertised list against a desired DNS address, and picking a
// network interface — are pure functions and are unit tested.
package detector

import (
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// DefaultTimeout is the default timeout for the active DHCP probe.
const DefaultTimeout = 10 * time.Second

// ParseDNSServers extracts the DNS server list (option 6) from a DHCPv4
// packet. Returns an error if the packet is nil or carries no DNS servers.
func ParseDNSServers(packet *dhcpv4.DHCPv4) ([]net.IP, error) {
	if packet == nil {
		return nil, fmt.Errorf("detector: nil DHCP packet")
	}

	servers := packet.DNS()
	if len(servers) == 0 {
		return nil, fmt.Errorf("detector: DHCP offer carries no DNS servers (option 6)")
	}

	return servers, nil
}

// HasDrifted reports whether the advertised DNS server list differs from the
// desired DNS address. Comparison is order-insensitive: it treats the
// advertised list as a set and checks whether the desired address is a
// member of it. Duplicate entries in the advertised list are ignored.
//
// Drift is defined as: the desired DNS address is NOT present among the
// advertised DNS servers.
func HasDrifted(advertised []net.IP, desired string) (bool, error) {
	desiredIP := net.ParseIP(desired)
	if desiredIP == nil {
		return false, fmt.Errorf("detector: invalid desired DNS address %q", desired)
	}

	for _, ip := range advertised {
		if ip.Equal(desiredIP) {
			return false, nil
		}
	}

	return true, nil
}

// PickInterface selects a usable network interface for the DHCP probe from a
// list of candidates: the first interface that is up, not loopback, and
// supports broadcast. Returns an error if none qualify.
//
// This is a pure function over the given slice, which makes it unit
// testable without depending on the host's real network interfaces.
func PickInterface(ifaces []net.Interface) (string, error) {
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		return iface.Name, nil
	}
	return "", fmt.Errorf("detector: no suitable network interface found")
}

// DedupIPs returns a new slice with duplicate IP addresses removed,
// preserving the order of first appearance.
func DedupIPs(ips []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(ips))
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ip)
	}
	return result
}
