package lib

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testWgCidr builds a WgCidr the way server_manager.go does -- PrefixFrom on
// the network base + 1 (the server's reserved IP) -- so its .Addr() matches
// a real running server's rather than the masked network address.
func testWgCidr(cidr string) netip.Prefix {
	p := netip.MustParsePrefix(cidr)
	return netip.PrefixFrom(p.Masked().Addr().Next(), p.Bits())
}

func TestIpipIfname(t *testing.T) {
	srv := &Server{Index: 0, WgCidr: testWgCidr("10.100.0.0/16")}
	name, err := srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 0, 2}))
	require.NoError(t, err)
	assert.Equal(t, "vp0-1", name)

	name, err = srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 1, 3}))
	require.NoError(t, err)
	assert.Equal(t, "vp0-258", name)

	srv = &Server{Index: 7, WgCidr: testWgCidr("10.100.0.0/16")}
	name, err = srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 255, 255}))
	require.NoError(t, err)
	assert.Equal(t, "vp7-65534", name)
}

// TestIpipIfnameWithinIfnamsiz locks in the reasoning from ipipIfname's doc
// comment: the "vp<index>-<offset>" name must stay within IFNAMSIZ (15
// visible chars) even at the largest possible index and offset for any
// realistic CIDR width.
func TestIpipIfnameWithinIfnamsiz(t *testing.T) {
	srv := &Server{Index: 65535, WgCidr: testWgCidr("10.100.0.0/16")}
	name, err := srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 255, 255}))
	require.NoError(t, err)
	assert.Equal(t, "vp65535-65534", name)
	assert.LessOrEqual(t, len(name), 15, "interface name exceeds IFNAMSIZ")
}

// TestIpipIfnameNoCollisionForWideCidr regression-tests the bug where two
// distinct peers inside a CIDR wider than /16 would produce the same
// interface name because only the low 16 bits of peerIP were used.
func TestIpipIfnameNoCollisionForWideCidr(t *testing.T) {
	srv := &Server{Index: 0, WgCidr: testWgCidr("10.0.0.0/8")}
	a, err := srv.ipipIfname(netip.AddrFrom4([4]byte{10, 0, 0, 2}))
	require.NoError(t, err)
	b, err := srv.ipipIfname(netip.AddrFrom4([4]byte{10, 1, 0, 2}))
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "names must differ for distinct peers in the same CIDR")
}

// TestIpipIfnameRejectsOversizedNames verifies the hard IFNAMSIZ guard so an
// extreme CIDR + server index combination fails loudly instead of silently
// truncating or colliding.
func TestIpipIfnameRejectsOversizedNames(t *testing.T) {
	// A /4 CIDR (28 host bits) plus the maximum server index yields a
	// 9-digit offset on top of "vp65535-" (8 chars): 8 + 9 = 17 > 15, so
	// this must error.
	srv := &Server{Index: 65535, WgCidr: testWgCidr("0.0.0.0/4")}
	_, err := srv.ipipIfname(netip.AddrFrom4([4]byte{15, 255, 255, 255}))
	assert.Error(t, err, "expected error for ifname exceeding IFNAMSIZ")
}

func TestIpipIfaceWildcard(t *testing.T) {
	assert.Equal(t, "vp0-+", (&Server{Index: 0}).ipipIfaceWildcard())
	assert.Equal(t, "vp42-+", (&Server{Index: 42}).ipipIfaceWildcard())
}

func TestIpipPeerAcceptRule(t *testing.T) {
	peerIP := netip.AddrFrom4([4]byte{10, 100, 0, 5})
	rule := ipipPeerAcceptRule("vp0-5", peerIP)
	assert.Equal(t, []string{
		"-i", "vp0-5",
		"-s", "10.100.0.5/32",
		"-j", "ACCEPT",
		"-m", "comment", "--comment",
		"vprox ipip accept peer 10.100.0.5 on vp0-5",
	}, rule)
}

func TestIpipPeerDropRule(t *testing.T) {
	rule := ipipPeerDropRule("vp0-5")
	assert.Equal(t, []string{
		"-i", "vp0-5",
		"-j", "DROP",
		"-m", "comment", "--comment",
		"vprox ipip drop spoofed on vp0-5",
	}, rule)
}
