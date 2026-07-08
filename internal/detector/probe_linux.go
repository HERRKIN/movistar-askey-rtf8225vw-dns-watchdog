//go:build linux

package detector

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

// Probe sends an active DHCP DISCOVER on the given interface and returns the
// DNS servers advertised in the resulting OFFER's option 6.
//
// A failed probe (e.g. no OFFER received, interface error) returns an error.
// Callers MUST NOT treat a probe error as DNS drift — it means the check
// itself could not complete, not that the DNS is wrong.
//
// Requires CAP_NET_RAW and host networking: it opens a raw socket to send
// and receive DHCP broadcast traffic directly on the LAN interface.
func Probe(iface string, timeout time.Duration) ([]net.IP, error) {
	if iface == "" {
		return nil, fmt.Errorf("detector: no network interface specified")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	client, err := nclient4.New(iface, nclient4.WithTimeout(timeout))
	if err != nil {
		return nil, fmt.Errorf("detector: failed to create DHCP client on %s: %w", iface, err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	offer, err := client.DiscoverOffer(ctx)
	if err != nil {
		return nil, fmt.Errorf("detector: DHCP DISCOVER on %s failed: %w", iface, err)
	}

	return ParseDNSServers(offer)
}
