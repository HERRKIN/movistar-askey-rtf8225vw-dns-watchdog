package remediator

import "testing"

func TestParseLANFields(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		want    LANPageFields
		wantErr bool
	}{
		{
			name: "input tags, name before value",
			html: `<html><body><form>
				<input name="gatewayIPaddress" value="192.168.1.1">
				<input name="gatewayNetmask" value="255.255.255.0">
				<select name="DHCPActive"><option value="0">Disabled</option><option value="1" selected>Enabled</option></select>
				<input name="startIPAddress" value="192.168.1.81">
				<input name="endIPAddress" value="192.168.1.219">
				<input name="DNSserver1" value="192.168.1.254">
				<input name="DNSserver2" value="192.168.1.254">
			</form></body></html>`,
			want: LANPageFields{
				GatewayIPAddress: "192.168.1.1",
				GatewayNetmask:   "255.255.255.0",
				DHCPActive:       "1",
				StartIPAddress:   "192.168.1.81",
				EndIPAddress:     "192.168.1.219",
				DNSServer1:       "192.168.1.254",
				DNSServer2:       "192.168.1.254",
			},
		},
		{
			name: "input tags, value before name",
			html: `<html><body><form>
				<input value="192.168.1.1" name="gatewayIPaddress">
				<input value="255.255.255.0" name="gatewayNetmask">
				<input value="1" name="DHCPActive">
				<input value="192.168.1.81" name="startIPAddress">
				<input value="192.168.1.219" name="endIPAddress">
				<input value="192.168.1.254" name="DNSserver1">
				<input value="192.168.1.254" name="DNSserver2">
			</form></body></html>`,
			want: LANPageFields{
				GatewayIPAddress: "192.168.1.1",
				GatewayNetmask:   "255.255.255.0",
				DHCPActive:       "1",
				StartIPAddress:   "192.168.1.81",
				EndIPAddress:     "192.168.1.219",
				DNSServer1:       "192.168.1.254",
				DNSServer2:       "192.168.1.254",
			},
		},
		{
			name: "select with selected before value",
			html: `<select name="DHCPActive"><option selected value="1">Enabled</option></select>
				<input name="gatewayIPaddress" value="192.168.1.1">
				<input name="gatewayNetmask" value="255.255.255.0">
				<input name="startIPAddress" value="192.168.1.81">
				<input name="endIPAddress" value="192.168.1.219">
				<input name="DNSserver1" value="192.168.1.254">
				<input name="DNSserver2" value="192.168.1.254">`,
			want: LANPageFields{
				GatewayIPAddress: "192.168.1.1",
				GatewayNetmask:   "255.255.255.0",
				DHCPActive:       "1",
				StartIPAddress:   "192.168.1.81",
				EndIPAddress:     "192.168.1.219",
				DNSServer1:       "192.168.1.254",
				DNSServer2:       "192.168.1.254",
			},
		},
		{
			name:    "missing fields returns error",
			html:    `<html><body>nothing here</body></html>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLANFields(tt.html)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseLANFields() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLANFields() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseLANFields() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBuildLANFieldsForRestore(t *testing.T) {
	current := LANPageFields{
		GatewayIPAddress: "192.168.1.1",
		GatewayNetmask:   "255.255.255.0",
		DHCPActive:       "1",
		StartIPAddress:   "192.168.1.81",
		EndIPAddress:     "192.168.1.219",
		DNSServer1:       "200.28.4.130",
		DNSServer2:       "200.28.4.129",
	}

	got := buildLANFieldsForRestore(current, "192.168.1.254")

	want := LANFields{
		EthIPAddress:  "192.168.1.1",
		EthSubnetMask: "255.255.255.0",
		EnableDHCPSrv: "1",
		DHCPEthStart:  "192.168.1.81",
		DHCPEthEnd:    "192.168.1.219",
		LANHostDNS:    "192.168.1.254,192.168.1.254",
		LANHostDHCP:   "1",
		LoginSupport:  "",
	}

	if got != want {
		t.Errorf("buildLANFieldsForRestore() = %+v, want %+v", got, want)
	}
}
