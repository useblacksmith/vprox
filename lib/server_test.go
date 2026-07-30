package lib

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GenerateKey()
	assert.NoError(t, err)
	return key
}

func peerWithPrefix(key wgtypes.Key, prefix string) wgtypes.Peer {
	ipnet := prefixToIPNet(netip.MustParsePrefix(prefix))
	return wgtypes.Peer{PublicKey: key, AllowedIPs: []net.IPNet{ipnet}}
}

func TestRestorePeerState(t *testing.T) {
	alloc := NewIpAllocator(netip.MustParsePrefix("10.1.0.0/24"))
	// Reserve the server's own address, as InitState does.
	assert.Equal(t, netip.MustParseAddr("10.1.0.1"), alloc.Allocate())

	k1 := mustKey(t)
	k2 := mustKey(t)
	k3 := mustKey(t)
	k4 := mustKey(t)
	k5 := mustKey(t)
	peers := []wgtypes.Peer{
		peerWithPrefix(k1, "10.1.0.2/32"),
		peerWithPrefix(k2, "10.1.0.7/32"),
		{PublicKey: k3},                   // no AllowedIPs
		peerWithPrefix(k4, "10.1.0.8/31"), // not a /32
		peerWithPrefix(k5, "10.2.0.2/32"), // outside the allocator prefix
	}

	restored := restorePeerState(peers, alloc)

	assert.Equal(t, map[wgtypes.Key]netip.Addr{
		k1: netip.MustParseAddr("10.1.0.2"),
		k2: netip.MustParseAddr("10.1.0.7"),
	}, restored.peerIPs)
	assert.ElementsMatch(t, []wgtypes.Key{k3, k4, k5}, restored.invalid)

	// Restored IPs are claimed in the allocator, so new allocations skip them.
	assert.Equal(t, netip.MustParseAddr("10.1.0.3"), alloc.Allocate())

	// A peer whose IP is already claimed (duplicate) is flagged as invalid.
	k6 := mustKey(t)
	dup := restorePeerState([]wgtypes.Peer{peerWithPrefix(k6, "10.1.0.2/32")}, alloc)
	assert.Empty(t, dup.peerIPs)
	assert.Equal(t, []wgtypes.Key{k6}, dup.invalid)
}

func TestPeerAssignedIp(t *testing.T) {
	key := mustKey(t)

	addr, ok := peerAssignedIp(peerWithPrefix(key, "10.1.0.9/32"))
	assert.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("10.1.0.9"), addr)

	_, ok = peerAssignedIp(wgtypes.Peer{PublicKey: key})
	assert.False(t, ok)

	_, ok = peerAssignedIp(peerWithPrefix(key, "10.1.0.0/24"))
	assert.False(t, ok)

	_, ok = peerAssignedIp(peerWithPrefix(key, "fd00::1/128"))
	assert.False(t, ok)
}
