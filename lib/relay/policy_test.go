package relay

import (
	"net/netip"
	"testing"
)

func TestPolicyTable(t *testing.T) {
	t.Parallel()
	p := NewPolicy(PolicyConfig{
		ExtraDenyPrefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		DenyPorts:         []uint16{25},
		OwnAddrs: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("205.234.200.247")}, nil
		},
	})
	cases := []struct {
		dst  string
		deny bool
	}{
		{"1.1.1.1:53", false},
		{"140.82.112.3:443", false},
		{"8.8.8.8:123", false},
		{"10.0.0.5:80", true},          // RFC1918
		{"172.31.255.1:80", true},      // RFC1918
		{"192.168.64.1:80", true},      // RFC1918 (the Mac's vmnet subnet)
		{"127.0.0.1:443", true},        // loopback
		{"169.254.169.254:80", true},   // link-local / metadata
		{"100.100.100.100:53", true},   // Tailscale CGNAT
		{"224.0.0.251:5353", true},     // multicast
		{"255.255.255.255:67", true},   // broadcast (240/4)
		{"0.0.0.0:80", true},           // unspecified
		{"205.234.200.247:22", true},   // the relay itself
		{"203.0.113.9:443", true},      // extra deny prefix (tunnel subnet)
		{"140.82.112.3:25", true},      // denied port
		{"140.82.112.3:0", true},       // port 0
		{"[2606:4700::1111]:53", true}, // no IPv6
	}
	for _, c := range cases {
		err := p.Check(netip.MustParseAddrPort(c.dst))
		if (err != nil) != c.deny {
			t.Errorf("%s: deny=%v got err=%v", c.dst, c.deny, err)
		}
	}
}

func TestPolicyOwnAddrsFailClosedOnError(t *testing.T) {
	t.Parallel()
	p := NewPolicy(PolicyConfig{OwnAddrs: func() ([]netip.Addr, error) {
		return nil, errTest
	}})
	// Own-address discovery failing must not disable the static deny-list.
	if err := p.Check(netip.MustParseAddrPort("10.1.2.3:80")); err == nil {
		t.Fatal("RFC1918 must still be denied")
	}
	if err := p.Check(netip.MustParseAddrPort("1.1.1.1:80")); err != nil {
		t.Fatalf("public destination should pass: %v", err)
	}
}

func TestPolicyIPv4MappedIsUnmapped(t *testing.T) {
	t.Parallel()
	p := NewPolicy(PolicyConfig{OwnAddrs: func() ([]netip.Addr, error) { return nil, nil }})
	if err := p.Check(netip.MustParseAddrPort("[::ffff:10.0.0.1]:80")); err == nil {
		t.Fatal("v4-mapped RFC1918 must be denied")
	}
	if err := p.Check(netip.MustParseAddrPort("[::ffff:1.1.1.1]:80")); err != nil {
		t.Fatalf("v4-mapped public should pass: %v", err)
	}
}

type testErr struct{}

func (testErr) Error() string { return "test error" }

var errTest = testErr{}
