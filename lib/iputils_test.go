package lib

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIpAllocatorClaim(t *testing.T) {
	ipa := NewIpAllocator(netip.MustParsePrefix("192.168.0.0/24"))

	// Claiming a free address succeeds; claiming it again fails.
	addr := netip.MustParseAddr("192.168.0.5")
	assert.True(t, ipa.Claim(addr))
	assert.False(t, ipa.Claim(addr))

	// Claiming an address outside the prefix fails.
	assert.False(t, ipa.Claim(netip.MustParseAddr("192.168.1.5")))

	// Claiming an address returned by Allocate fails.
	first := ipa.Allocate()
	assert.Equal(t, netip.MustParseAddr("192.168.0.1"), first)
	assert.False(t, ipa.Claim(first))

	// Allocate skips claimed addresses.
	assert.True(t, ipa.Claim(netip.MustParseAddr("192.168.0.2")))
	assert.True(t, ipa.Claim(netip.MustParseAddr("192.168.0.3")))
	assert.Equal(t, netip.MustParseAddr("192.168.0.4"), ipa.Allocate())

	// A freed address can be claimed again.
	assert.True(t, ipa.Free(addr))
	assert.True(t, ipa.Claim(addr))
}

func TestAfterOneIpBlock(t *testing.T) {
	ip1 := netip.AddrFrom4([4]byte{192, 168, 1, 0})
	ip2 := netip.AddrFrom4([4]byte{192, 168, 2, 0})
	assert.Equal(t, AfterCountIpBlock(ip1, 24, 1), ip2, "next ip mismatch")

	ip2 = netip.AddrFrom4([4]byte{192, 168, 1, 16})
	assert.Equal(t, AfterCountIpBlock(ip1, 28, 1), ip2, "next ip mismatch")

	ip2 = netip.AddrFrom4([4]byte{193, 168, 1, 0})
	assert.Equal(t, AfterCountIpBlock(ip1, 8, 1), ip2, "next ip mismatch")
}

func TestAfterCountIpBlock(t *testing.T) {
	ip1 := netip.AddrFrom4([4]byte{192, 168, 1, 0})
	ip2 := netip.AddrFrom4([4]byte{192, 168, 6, 0})
	assert.Equal(t, AfterCountIpBlock(ip1, 24, 5), ip2)

	ip2 = netip.AddrFrom4([4]byte{192, 168, 1, 64})
	assert.Equal(t, AfterCountIpBlock(ip1, 28, 4), ip2)

	ip2 = netip.AddrFrom4([4]byte{192, 168, 2, 128})
	assert.Equal(t, AfterCountIpBlock(ip1, 25, 3), ip2)
}
