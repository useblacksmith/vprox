package lib

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIpipIfname(t *testing.T) {
	srv := &Server{Index: 0}
	assert.Equal(t, "vp0-1", srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 0, 1})))
	assert.Equal(t, "vp0-258", srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 1, 2})))

	srv = &Server{Index: 7}
	assert.Equal(t, "vp7-65535", srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 255, 255})))
}

// TestIpipIfnameWithinIfnamsiz locks in the reasoning from ipipIfname's doc
// comment: the "vp<index>-<host>" name must stay within IFNAMSIZ (15 visible
// chars) even at the largest possible index and host values.
func TestIpipIfnameWithinIfnamsiz(t *testing.T) {
	srv := &Server{Index: 65535} // max uint16
	name := srv.ipipIfname(netip.AddrFrom4([4]byte{10, 100, 255, 255}))
	assert.Equal(t, "vp65535-65535", name)
	assert.LessOrEqual(t, len(name), 15, "interface name exceeds IFNAMSIZ")
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
