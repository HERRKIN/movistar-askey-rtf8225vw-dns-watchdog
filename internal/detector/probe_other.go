//go:build !linux

package detector

import (
	"fmt"
	"net"
	"runtime"
	"time"
)

// Probe is not supported on non-linux platforms: the active DHCP probe
// needs a raw socket (CAP_NET_RAW) via github.com/insomniacslk/dhcp's
// nclient4 package, which only builds/runs on linux. This stub exists so
// the detector package — and its pure, unit-tested logic — still builds on
// a developer's machine (e.g. macOS). The real deployment target is always
// linux (Docker, network_mode: host + CAP_NET_RAW).
func Probe(iface string, timeout time.Duration) ([]net.IP, error) {
	return nil, fmt.Errorf("detector: active DHCP probe is only supported on linux, got GOOS=%s", runtime.GOOS)
}
