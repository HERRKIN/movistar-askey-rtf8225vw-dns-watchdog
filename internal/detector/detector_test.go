package detector

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func mustPacket(t *testing.T, dns ...net.IP) *dhcpv4.DHCPv4 {
	t.Helper()
	modifiers := []dhcpv4.Modifier{}
	if len(dns) > 0 {
		modifiers = append(modifiers, dhcpv4.WithDNS(dns...))
	}
	pkt, err := dhcpv4.New(modifiers...)
	if err != nil {
		t.Fatalf("failed to build test DHCPv4 packet: %v", err)
	}
	return pkt
}

func TestParseDNSServers(t *testing.T) {
	tests := []struct {
		name    string
		packet  *dhcpv4.DHCPv4
		want    []net.IP
		wantErr bool
	}{
		{
			name:   "single DNS server",
			packet: mustPacket(t, net.ParseIP("192.168.1.254")),
			want:   []net.IP{net.ParseIP("192.168.1.254")},
		},
		{
			name:   "two DNS servers",
			packet: mustPacket(t, net.ParseIP("200.28.4.130"), net.ParseIP("200.28.4.129")),
			want:   []net.IP{net.ParseIP("200.28.4.130"), net.ParseIP("200.28.4.129")},
		},
		{
			name:    "no DNS option present",
			packet:  mustPacket(t),
			wantErr: true,
		},
		{
			name:    "nil packet",
			packet:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDNSServers(tt.packet)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseDNSServers() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDNSServers() unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseDNSServers() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if !got[i].Equal(tt.want[i]) {
					t.Errorf("ParseDNSServers()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestHasDrifted(t *testing.T) {
	tests := []struct {
		name       string
		advertised []net.IP
		desired    string
		want       bool
		wantErr    bool
	}{
		{
			name:       "desired DNS present, no drift",
			advertised: []net.IP{net.ParseIP("192.168.1.254")},
			desired:    "192.168.1.254",
			want:       false,
		},
		{
			name:       "desired DNS present among multiple, order does not matter",
			advertised: []net.IP{net.ParseIP("200.28.4.130"), net.ParseIP("192.168.1.254")},
			desired:    "192.168.1.254",
			want:       false,
		},
		{
			name:       "desired DNS missing, drift detected",
			advertised: []net.IP{net.ParseIP("200.28.4.130"), net.ParseIP("200.28.4.129")},
			desired:    "192.168.1.254",
			want:       true,
		},
		{
			name:       "empty advertised list is drift",
			advertised: []net.IP{},
			desired:    "192.168.1.254",
			want:       true,
		},
		{
			name:       "invalid desired address returns error",
			advertised: []net.IP{net.ParseIP("192.168.1.254")},
			desired:    "not-an-ip",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HasDrifted(tt.advertised, tt.desired)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("HasDrifted() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("HasDrifted() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("HasDrifted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPickInterface(t *testing.T) {
	tests := []struct {
		name    string
		ifaces  []net.Interface
		want    string
		wantErr bool
	}{
		{
			name: "picks first up, non-loopback, broadcast-capable interface",
			ifaces: []net.Interface{
				{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback},
				{Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast},
				{Name: "eth1", Flags: net.FlagUp | net.FlagBroadcast},
			},
			want: "eth0",
		},
		{
			name: "skips interfaces that are down",
			ifaces: []net.Interface{
				{Name: "eth0", Flags: net.FlagBroadcast}, // not up
				{Name: "eth1", Flags: net.FlagUp | net.FlagBroadcast},
			},
			want: "eth1",
		},
		{
			name: "skips interfaces without broadcast",
			ifaces: []net.Interface{
				{Name: "tun0", Flags: net.FlagUp},
				{Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast},
			},
			want: "eth0",
		},
		{
			name:    "no candidates returns error",
			ifaces:  []net.Interface{{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}},
			wantErr: true,
		},
		{
			name:    "empty list returns error",
			ifaces:  []net.Interface{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PickInterface(tt.ifaces)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("PickInterface() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("PickInterface() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("PickInterface() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDedupIPs(t *testing.T) {
	tests := []struct {
		name string
		in   []net.IP
		want []net.IP
	}{
		{
			name: "no duplicates",
			in:   []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")},
			want: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")},
		},
		{
			name: "duplicates removed, order preserved",
			in:   []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")},
			want: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")},
		},
		{
			name: "empty input",
			in:   []net.IP{},
			want: []net.IP{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DedupIPs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("DedupIPs() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if !got[i].Equal(tt.want[i]) {
					t.Errorf("DedupIPs()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
