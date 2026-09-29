package lib

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

// legacyIpipPrefix is the interface-name prefix of the IPIP tunnels that
// earlier vprox releases created per macOS client: "vp<index>-<offset>",
// offset being the peer's inner IP distance from WgCidr's base address.
func (srv *Server) legacyIpipPrefix() string {
	return fmt.Sprintf("vp%d-", srv.Index)
}

// legacyIpipPeer recovers a legacy tunnel's inner peer IP from its name.
func (srv *Server) legacyIpipPeer(ifname string) (netip.Addr, bool) {
	offset, err := strconv.ParseUint(strings.TrimPrefix(ifname, srv.legacyIpipPrefix()), 10, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	base := srv.WgCidr.Addr().As4()
	n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	n += uint32(offset)
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
}

// removeLegacyIpip deletes the kernel state left behind by the IPIP/ESP
// tunnel dataplane that earlier vprox releases ran for macOS clients: this
// server's vp<index>-* tunnels (and with them their /32 host routes), the
// per-tunnel FORWARD filters, the MSS clamp rules and the ESP SAs/policies
// between BindAddr and each tunnel's remote.
//
// Deploys leave the kernel dataplane in place, so a host upgraded from such
// a release still carries all of it. A leftover /32 outranks WireGuard's
// connected prefix and ipAllocator does not know the address, so a peer
// that is later allocated the same inner IP would have its return traffic
// blackholed into the dead tunnel. Startup therefore fails if any of it
// cannot be removed.
func (srv *Server) removeLegacyIpip() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %v", err)
	}
	var errs []error
	for _, link := range links {
		ifname := link.Attrs().Name
		if !strings.HasPrefix(ifname, srv.legacyIpipPrefix()) {
			continue
		}
		var remote net.IP
		if tun, ok := link.(*netlink.Iptun); ok {
			remote = tun.Remote
		}
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Errorf("delete legacy ipip link %s: %v", ifname, err))
			continue
		}
		log.Printf("[%v] removed legacy ipip tunnel %s (remote %v)", srv.BindAddr, ifname, remote)
		if err := srv.removeLegacyIpipFilter(ifname); err != nil {
			errs = append(errs, err)
		}
		if client, ok := netip.AddrFromSlice(remote); ok {
			if err := srv.removeLegacyIpipEsp(client.Unmap()); err != nil {
				errs = append(errs, fmt.Errorf("remove legacy esp for %v: %v", client, err))
			}
		}
	}
	if err := srv.removeLegacyIpipMssRules(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// removeLegacyIpipFilter removes the FORWARD accept/drop pair that guarded
// a legacy tunnel's inner source IP. The tunnel is already gone, so both
// rules match nothing and their removal order is irrelevant.
func (srv *Server) removeLegacyIpipFilter(ifname string) error {
	drop := []string{
		"-i", ifname,
		"-j", "DROP",
		"-m", "comment", "--comment",
		fmt.Sprintf("vprox ipip drop spoofed on %s", ifname),
	}
	if err := srv.Ipt.DeleteIfExists("filter", "FORWARD", drop...); err != nil {
		return fmt.Errorf("remove legacy ipip drop rule for %s: %v", ifname, err)
	}
	peerIP, ok := srv.legacyIpipPeer(ifname)
	if !ok {
		return nil
	}
	accept := []string{
		"-i", ifname,
		"-s", fmt.Sprintf("%v/32", peerIP),
		"-j", "ACCEPT",
		"-m", "comment", "--comment",
		fmt.Sprintf("vprox ipip accept peer %v on %s", peerIP, ifname),
	}
	if err := srv.Ipt.DeleteIfExists("filter", "FORWARD", accept...); err != nil {
		return fmt.Errorf("remove legacy ipip accept rule for %s: %v", ifname, err)
	}
	return nil
}

// removeLegacyIpipMssRules removes the wildcard TCP MSS clamp that earlier
// releases installed for this server's tunnels at every startup, so it is
// present on an upgraded host even when no tunnel ever existed.
func (srv *Server) removeLegacyIpipMssRules() error {
	wildcard := srv.legacyIpipPrefix() + "+"
	for _, r := range []struct{ flag, dir string }{{"-o", "outbound"}, {"-i", "inbound"}} {
		rule := []string{
			r.flag, wildcard,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--clamp-mss-to-pmtu",
			"-m", "comment", "--comment",
			fmt.Sprintf("vprox ipip TCP MSS %s rule for %s", r.dir, srv.Ifname()),
		}
		if err := srv.Ipt.DeleteIfExists("mangle", "FORWARD", rule...); err != nil {
			return fmt.Errorf("remove legacy ipip %s MSS rule: %v", r.dir, err)
		}
	}
	return nil
}
