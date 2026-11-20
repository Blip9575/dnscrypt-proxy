package main

import (
	"net"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/BurntSushi/toml"
)

func ecsTestQuery(withClientSubnet bool) *dns.Msg {
	msg := dns.NewMsg("example.com.", dns.TypeA)
	msg.UDPSize = 1232
	msg.Pseudo = append(msg.Pseudo, &dns.COOKIE{Cookie: "0102030405060708"})
	if withClientSubnet {
		msg.Pseudo = append(msg.Pseudo, &dns.SUBNET{Family: 1, Netmask: 32, Address: netip.MustParseAddr("192.168.0.71")})
	}
	return msg
}

func ecsTestSubnets(msg *dns.Msg) []*dns.SUBNET {
	var subnets []*dns.SUBNET
	for _, rr := range msg.Pseudo {
		if subnet, ok := rr.(*dns.SUBNET); ok {
			subnets = append(subnets, subnet)
		}
	}
	return subnets
}

func ecsTestHasCookie(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.COOKIE); ok {
			return true
		}
	}
	return false
}

func TestPluginECS(t *testing.T) {
	_, configured, _ := net.ParseCIDR("192.0.2.0/24")
	tests := []struct {
		name             string
		nets             []*net.IPNet
		passthrough      bool
		withClientSubnet bool
		want             string // expected subnet address, "" for none
	}{
		{"passthrough keeps the client subnet", []*net.IPNet{configured}, true, true, "192.168.0.71"},
		{"passthrough adds a subnet when the client sent none", []*net.IPNet{configured}, true, false, "192.0.2.0"},
		{"no passthrough removes the client subnet", nil, false, true, ""},
		{"no passthrough replaces the client subnet", []*net.IPNet{configured}, false, true, "192.0.2.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := PluginECS{nets: tt.nets, passthrough: tt.passthrough}
			pluginsState := PluginsState{maxPayloadSize: MaxDNSUDPPacketSize - ResponseOverhead}
			msg := ecsTestQuery(tt.withClientSubnet)
			if err := plugin.Eval(&pluginsState, msg); err != nil {
				t.Fatal(err)
			}
			subnets := ecsTestSubnets(msg)
			if tt.want == "" {
				if len(subnets) != 0 {
					t.Errorf("subnets: %v, want none", subnets)
				}
			} else if len(subnets) != 1 || subnets[0].Address.String() != tt.want {
				t.Errorf("subnets: %v, want one with address %s", subnets, tt.want)
			}
			if !ecsTestHasCookie(msg) {
				t.Error("other EDNS options must be kept")
			}
		})
	}
}

func TestEDNSClientSubnetPassthroughDefault(t *testing.T) {
	for _, tt := range []struct {
		toml string
		want bool
	}{
		{"", true},
		{"edns_client_subnet = ['192.0.2.0/24']", true},
		{"edns_client_subnet_passthrough = false", false},
		{"edns_client_subnet_passthrough = true", true},
	} {
		config := newConfig()
		if _, err := toml.Decode(tt.toml, &config); err != nil {
			t.Fatal(err)
		}
		if config.EDNSClientSubnetPassthrough != tt.want {
			t.Errorf("%q: edns_client_subnet_passthrough = %v, want %v", tt.toml, config.EDNSClientSubnetPassthrough, tt.want)
		}
	}
}
