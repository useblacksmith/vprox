package lib

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
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

// TestIpipPeerFromIfname verifies the ifname parser used by restore
// round-trips with ipipIfname and rejects names that don't belong to
// this server's IPIP interfaces.
func TestIpipPeerFromIfname(t *testing.T) {
	srv := &Server{Index: 7, WgCidr: testWgCidr("10.100.0.0/16")}
	for _, peer := range []netip.Addr{
		netip.AddrFrom4([4]byte{10, 100, 0, 2}),
		netip.AddrFrom4([4]byte{10, 100, 1, 3}),
		netip.AddrFrom4([4]byte{10, 100, 255, 255}),
	} {
		name, err := srv.ipipIfname(peer)
		require.NoError(t, err)
		got, ok := srv.ipipPeerFromIfname(name)
		require.True(t, ok, "expected %s to parse", name)
		assert.Equal(t, peer, got)
	}

	for _, name := range []string{"vp8-1", "eth0", "vp7-", "vp7-x", "vproxy7"} {
		_, ok := srv.ipipPeerFromIfname(name)
		assert.False(t, ok, "expected %s to be rejected", name)
	}
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

func TestUsableIpipRemote(t *testing.T) {
	_, ok := usableIpipRemote(nil)
	assert.False(t, ok)
	_, ok = usableIpipRemote(net.IP{})
	assert.False(t, ok)
	_, ok = usableIpipRemote(net.IPv4zero)
	assert.False(t, ok)
	_, ok = usableIpipRemote(net.ParseIP("::1"))
	assert.False(t, ok)

	addr, ok := usableIpipRemote(net.ParseIP("203.0.113.9"))
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("203.0.113.9"), addr)

	addr, ok = usableIpipRemote(net.ParseIP("::ffff:192.0.2.1"))
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), addr)
}

func TestClassifyIpipLink(t *testing.T) {
	srv := &Server{Index: 0, WgCidr: testWgCidr("10.100.0.0/16")}
	parse := srv.ipipPeerFromIfname
	remote := net.ParseIP("203.0.113.9")

	ignored := classifyIpipLink("eth0", false, nil, parse)
	assert.Equal(t, ipipRestoreIgnore, ignored.Kind)

	ignored = classifyIpipLink("vp1-1", true, remote, parse)
	assert.Equal(t, ipipRestoreIgnore, ignored.Kind)

	notTun := classifyIpipLink("vp0-1", false, remote, parse)
	assert.Equal(t, ipipRestoreDelete, notTun.Kind)
	assert.Equal(t, ipipRestoreReasonNotIptun, notTun.Reason)
	assert.Equal(t, netip.MustParseAddr("10.100.0.2"), notTun.PeerIP)

	noRemote := classifyIpipLink("vp0-1", true, nil, parse)
	assert.Equal(t, ipipRestoreDelete, noRemote.Kind)
	assert.Equal(t, ipipRestoreReasonUnusableRemote, noRemote.Reason)

	unspec := classifyIpipLink("vp0-1", true, net.IPv4zero, parse)
	assert.Equal(t, ipipRestoreDelete, unspec.Kind)
	assert.Equal(t, ipipRestoreReasonUnusableRemote, unspec.Reason)

	v6 := classifyIpipLink("vp0-1", true, net.ParseIP("2001:db8::1"), parse)
	assert.Equal(t, ipipRestoreDelete, v6.Kind)
	assert.Equal(t, ipipRestoreReasonUnusableRemote, v6.Reason)

	adopt := classifyIpipLink("vp0-1", true, remote, parse)
	assert.Equal(t, ipipRestoreAdopt, adopt.Kind)
	assert.Equal(t, "vp0-1", adopt.Ifname)
	assert.Equal(t, netip.MustParseAddr("10.100.0.2"), adopt.PeerIP)
	assert.Equal(t, netip.MustParseAddr("203.0.113.9"), adopt.Remote)
}

// testIpipRestoreServer mirrors InitState's allocator setup: WgCidr.Addr()
// is reserved so vp0-1 is the first peer IP (10.100.0.2).
func testIpipRestoreServer() *Server {
	cidr := testWgCidr("10.100.0.0/16")
	srv := &Server{Index: 0, WgCidr: cidr, ipAllocator: NewIpAllocator(cidr)}
	_ = srv.ipAllocator.Allocate()
	return srv
}

func TestPlanIpipRestoreAdoptsValidTunnels(t *testing.T) {
	srv := testIpipRestoreServer()
	a := classifyIpipLink("vp0-1", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	b := classifyIpipLink("vp0-2", true, net.ParseIP("203.0.113.2"), srv.ipipPeerFromIfname)
	adopt, del := planIpipRestore([]ipipRestoreCandidate{a, b}, srv.ipAllocator.Claim)
	require.Len(t, adopt, 2)
	assert.Empty(t, del)
	assert.Equal(t, "vp0-1", adopt[0].Ifname)
	assert.Equal(t, "vp0-2", adopt[1].Ifname)
	assert.False(t, srv.ipAllocator.Claim(netip.MustParseAddr("10.100.0.2")))
	assert.False(t, srv.ipAllocator.Claim(netip.MustParseAddr("10.100.0.3")))
}

func TestPlanIpipRestoreDeletesDuplicateRemote(t *testing.T) {
	srv := testIpipRestoreServer()
	first := classifyIpipLink("vp0-1", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	dup := classifyIpipLink("vp0-2", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	adopt, del := planIpipRestore([]ipipRestoreCandidate{first, dup}, srv.ipAllocator.Claim)
	require.Len(t, adopt, 1)
	assert.Equal(t, "vp0-1", adopt[0].Ifname)
	require.Len(t, del, 1)
	assert.Equal(t, "vp0-2", del[0].Ifname)
	assert.Equal(t, ipipRestoreReasonDuplicateRemote, del[0].Reason)
	// Duplicate's inner IP was not claimed, so it remains free after the
	// leftover iface is deleted.
	assert.True(t, srv.ipAllocator.Claim(netip.MustParseAddr("10.100.0.3")))
	assert.False(t, srv.ipAllocator.Claim(netip.MustParseAddr("10.100.0.2")))
}

func TestPlanIpipRestoreDeletesWhenWGOwnsInnerIP(t *testing.T) {
	srv := testIpipRestoreServer()
	require.True(t, srv.ipAllocator.Claim(netip.MustParseAddr("10.100.0.2")))
	c := classifyIpipLink("vp0-1", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	adopt, del := planIpipRestore([]ipipRestoreCandidate{c}, srv.ipAllocator.Claim)
	assert.Empty(t, adopt)
	require.Len(t, del, 1)
	assert.Equal(t, ipipRestoreReasonClaimFailed, del[0].Reason)
}

func TestPlanIpipRestoreDeletesDuplicateInnerIP(t *testing.T) {
	srv := testIpipRestoreServer()
	a := classifyIpipLink("vp0-1", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	b := classifyIpipLink("vp0-01", true, net.ParseIP("203.0.113.2"), srv.ipipPeerFromIfname)
	adopt, del := planIpipRestore([]ipipRestoreCandidate{a, b}, srv.ipAllocator.Claim)
	require.Len(t, adopt, 1)
	assert.Equal(t, "vp0-1", adopt[0].Ifname)
	require.Len(t, del, 1)
	assert.Equal(t, "vp0-01", del[0].Ifname)
	assert.Equal(t, ipipRestoreReasonClaimFailed, del[0].Reason)
}

func TestPlanIpipRestoreSecondRemoteAdoptedIfFirstClaimFails(t *testing.T) {
	srv := testIpipRestoreServer()
	require.True(t, srv.ipAllocator.Claim(netip.MustParseAddr("10.100.0.2")))
	first := classifyIpipLink("vp0-1", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	second := classifyIpipLink("vp0-2", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	adopt, del := planIpipRestore([]ipipRestoreCandidate{first, second}, srv.ipAllocator.Claim)
	require.Len(t, adopt, 1)
	assert.Equal(t, "vp0-2", adopt[0].Ifname)
	require.Len(t, del, 1)
	assert.Equal(t, "vp0-1", del[0].Ifname)
	assert.Equal(t, ipipRestoreReasonClaimFailed, del[0].Reason)
}

func TestPlanIpipRestoreDeletesOutsidePrefix(t *testing.T) {
	cidr := testWgCidr("10.100.0.0/30")
	srv := &Server{Index: 0, WgCidr: cidr, ipAllocator: NewIpAllocator(cidr)}
	_ = srv.ipAllocator.Allocate()
	c := classifyIpipLink("vp0-5", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	assert.Equal(t, ipipRestoreAdopt, c.Kind)
	adopt, del := planIpipRestore([]ipipRestoreCandidate{c}, srv.ipAllocator.Claim)
	assert.Empty(t, adopt)
	require.Len(t, del, 1)
	assert.Equal(t, ipipRestoreReasonClaimFailed, del[0].Reason)
}

func TestPlanIpipRestoreIgnoresUnrelatedAndDeletesClassifiedOrphans(t *testing.T) {
	srv := testIpipRestoreServer()
	ignore := classifyIpipLink("eth0", false, nil, srv.ipipPeerFromIfname)
	orphan := classifyIpipLink("vp0-1", false, nil, srv.ipipPeerFromIfname)
	good := classifyIpipLink("vp0-2", true, net.ParseIP("203.0.113.2"), srv.ipipPeerFromIfname)
	adopt, del := planIpipRestore([]ipipRestoreCandidate{ignore, orphan, good}, srv.ipAllocator.Claim)
	require.Len(t, adopt, 1)
	assert.Equal(t, "vp0-2", adopt[0].Ifname)
	require.Len(t, del, 1)
	assert.Equal(t, "vp0-1", del[0].Ifname)
	assert.Equal(t, ipipRestoreReasonNotIptun, del[0].Reason)
}

// TestIpipAdoptedRemotes verifies the ESP-protection set used by restore
// teardown: a rejected duplicate-remote leftover shares its (server,
// client) pair -- and therefore its kernel ESP state -- with the adopted
// tunnel, so its Remote must be in the protected set.
func TestIpipAdoptedRemotes(t *testing.T) {
	srv := testIpipRestoreServer()
	adopted := classifyIpipLink("vp0-1", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	dup := classifyIpipLink("vp0-2", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	orphan := classifyIpipLink("vp0-3", false, nil, srv.ipipPeerFromIfname)

	adopt, del := planIpipRestore([]ipipRestoreCandidate{adopted, dup, orphan}, srv.ipAllocator.Claim)
	require.Len(t, adopt, 1)
	require.Len(t, del, 2)

	remotes := ipipAdoptedRemotes(adopt)
	require.Len(t, remotes, 1)

	for _, d := range del {
		_, owned := remotes[d.Remote]
		switch d.Reason {
		case ipipRestoreReasonDuplicateRemote:
			assert.True(t, owned,
				"duplicate remote shares the adopted pair's ESP state and must be protected")
		case ipipRestoreReasonNotIptun:
			assert.False(t, owned, "orphan without usable remote is not protected")
		}
	}
}

// TestIpipAdoptedRemotesDistinctRemoteNotProtected: a deleted leftover with
// its own (non-adopted) Remote keeps today's behavior -- its ESP state is
// removed.
func TestIpipAdoptedRemotesDistinctRemoteNotProtected(t *testing.T) {
	srv := testIpipRestoreServer()
	require.True(t, srv.ipAllocator.Claim(netip.MustParseAddr("10.100.0.3")))
	adopted := classifyIpipLink("vp0-1", true, net.ParseIP("203.0.113.1"), srv.ipipPeerFromIfname)
	// Claim for vp0-2 (10.100.0.3) fails, so it is deleted, but its Remote
	// differs from every adopted tunnel's.
	loser := classifyIpipLink("vp0-2", true, net.ParseIP("203.0.113.2"), srv.ipipPeerFromIfname)

	adopt, del := planIpipRestore([]ipipRestoreCandidate{adopted, loser}, srv.ipAllocator.Claim)
	require.Len(t, adopt, 1)
	require.Len(t, del, 1)

	remotes := ipipAdoptedRemotes(adopt)
	_, owned := remotes[del[0].Remote]
	assert.False(t, owned, "a delete with its own remote must not be ESP-protected")
	_, owned = remotes[netip.MustParseAddr("203.0.113.1")]
	assert.True(t, owned)
}

func TestIpipAdoptedRemotesEmpty(t *testing.T) {
	assert.Empty(t, ipipAdoptedRemotes(nil))
	assert.Empty(t, ipipAdoptedRemotes([]ipipRestoreCandidate{{Ifname: "vp0-1"}}),
		"zero Remote must not enter the set")
}

// TestTearDownIpipSequenceOrder locks in the teardown order contract: the
// per-peer FORWARD filters (spoof protection) are removed only after the
// link delete confirms the iface is gone. A failed delete means a live
// tunnel may remain, and it must keep its filters.
func TestTearDownIpipSequenceOrder(t *testing.T) {
	t.Run("delete failure keeps filters", func(t *testing.T) {
		filtersRemoved := false
		err := tearDownIpipSequence(
			func() error { return fmt.Errorf("link busy") },
			func() { filtersRemoved = true },
		)
		require.Error(t, err, "caller must not Free the inner IP")
		assert.False(t, filtersRemoved,
			"filters must survive when the link may still exist")
	})

	t.Run("delete success removes filters", func(t *testing.T) {
		filtersRemoved := false
		err := tearDownIpipSequence(
			func() error { return nil },
			func() { filtersRemoved = true },
		)
		require.NoError(t, err)
		assert.True(t, filtersRemoved)
	})

	t.Run("filters removed after delete, not before", func(t *testing.T) {
		var order []string
		err := tearDownIpipSequence(
			func() error { order = append(order, "delete"); return nil },
			func() { order = append(order, "filters") },
		)
		require.NoError(t, err)
		assert.Equal(t, []string{"delete", "filters"}, order)
	})
}

// TestIpipLinkNotFound is the teardown/Free gate: only LinkNotFound means
// the kernel object is gone and the inner IP may be Freed. nil (iface still
// present) and any other lookup error must not Free.
func TestIpipLinkNotFound(t *testing.T) {
	assert.False(t, ipipLinkNotFound(nil), "iface still exists")
	assert.False(t, ipipLinkNotFound(fmt.Errorf("netlink: busy")), "may still exist")
	notFound := netlink.LinkNotFoundError{}
	assert.True(t, ipipLinkNotFound(notFound))
	assert.True(t, ipipLinkNotFound(wrappedLinkNotFound{notFound}))
}

type wrappedLinkNotFound struct{ err error }

func (w wrappedLinkNotFound) Error() string { return "wrap" }
func (w wrappedLinkNotFound) Unwrap() error { return w.err }

// TestIpipClaimFreeSequencing documents the restore/teardown allocator
// contract: Claim at adopt, Free only after the iface is confirmed gone.
func TestIpipClaimFreeSequencing(t *testing.T) {
	alloc := NewIpAllocator(netip.MustParsePrefix("10.100.0.0/16"))
	ip := netip.MustParseAddr("10.100.0.2")
	require.True(t, alloc.Claim(ip))
	assert.False(t, alloc.Claim(ip), "teardown failure must not Free; IP stays claimed")
	require.True(t, alloc.Free(ip), "LinkNotFound: Free after iface is gone")
	require.True(t, alloc.Claim(ip), "address can be reused only after Free")
}
