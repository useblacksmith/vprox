package lib

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
)

// ipProtoIpip is the IP protocol number of IP-in-IP, the selector protocol
// of the legacy tunnels' require-ESP xfrm policies.
const ipProtoIpip = 4

// removeLegacyIpipEsp deletes the ESP SAs and the require-ESP policies that
// a legacy tunnel installed between BindAddr and clientIP, in both
// directions. SPIs are not known after a restart, so everything is keyed on
// the address pair.
func (srv *Server) removeLegacyIpipEsp(clientIP netip.Addr) error {
	server := addrToIp(srv.BindAddr)
	client := addrToIp(clientIP)
	var errs []error

	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list xfrm policies: %v", err)
	}
	for i := range policies {
		pol := &policies[i]
		if pol.Proto != ipProtoIpip || pol.Src == nil || pol.Dst == nil {
			continue
		}
		pair := (pol.Src.IP.Equal(client) && pol.Dst.IP.Equal(server)) ||
			(pol.Src.IP.Equal(server) && pol.Dst.IP.Equal(client))
		if !pair {
			continue
		}
		if err := netlink.XfrmPolicyDel(pol); err != nil && !xfrmNotFound(err) {
			errs = append(errs, fmt.Errorf("delete %v esp policy: %v", pol.Dir, err))
		}
	}

	states, err := netlink.XfrmStateList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list xfrm states: %v", err)
	}
	for i := range states {
		s := &states[i]
		if s.Proto != netlink.XFRM_PROTO_ESP {
			continue
		}
		pair := (s.Src.Equal(client) && s.Dst.Equal(server)) ||
			(s.Src.Equal(server) && s.Dst.Equal(client))
		if !pair {
			continue
		}
		if err := netlink.XfrmStateDel(s); err != nil && !xfrmNotFound(err) {
			errs = append(errs, fmt.Errorf("delete esp state spi 0x%x: %v", s.Spi, err))
			continue
		}
		log.Printf("[%v] removed legacy esp state for %v (spi 0x%x)", srv.BindAddr, clientIP, s.Spi)
	}
	return errors.Join(errs...)
}

func xfrmNotFound(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT)
}
