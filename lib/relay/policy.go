package relay

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultDenyPrefixes is the destination deny-list applied on top of the
// relay's own addresses. The relay dials as a local process, so the
// FORWARD chain that guards the IPIP path does not apply; these prefixes
// keep a guest from reaching the server's private, link-local, Tailscale
// and tunnel neighbours.
func DefaultDenyPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
}

// PolicyError explains a refused destination.
type PolicyError struct {
	Dst    netip.AddrPort
	Reason string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("destination %s denied: %s", e.Dst, e.Reason)
}

// Policy decides which destinations a relayed stream may reach.
type Policy struct {
	denyPrefixes []netip.Prefix
	denyPorts    map[uint16]struct{}

	// ownAddrs is refreshed lazily from the host's interfaces so a newly
	// added static IP or tunnel address is covered without a restart.
	ownAddrsFn      func() ([]netip.Addr, error)
	ownAddrsTTL     time.Duration
	ownMu           sync.Mutex
	ownAddrs        map[netip.Addr]struct{}
	ownAddrsRefresh time.Time
}

// PolicyConfig configures a Policy.
type PolicyConfig struct {
	// DenyPrefixes replaces DefaultDenyPrefixes when non-nil.
	DenyPrefixes []netip.Prefix
	// ExtraDenyPrefixes are added to the deny-list (tunnel subnets etc).
	ExtraDenyPrefixes []netip.Prefix
	// DenyPorts refuses any destination on these ports.
	DenyPorts []uint16
	// OwnAddrs overrides interface discovery (tests).
	OwnAddrs func() ([]netip.Addr, error)
}

// NewPolicy builds a Policy.
func NewPolicy(cfg PolicyConfig) *Policy {
	p := &Policy{
		denyPorts:   make(map[uint16]struct{}, len(cfg.DenyPorts)),
		ownAddrsFn:  cfg.OwnAddrs,
		ownAddrsTTL: 10 * time.Second,
	}
	if cfg.DenyPrefixes != nil {
		p.denyPrefixes = append(p.denyPrefixes, cfg.DenyPrefixes...)
	} else {
		p.denyPrefixes = DefaultDenyPrefixes()
	}
	p.denyPrefixes = append(p.denyPrefixes, cfg.ExtraDenyPrefixes...)
	for _, port := range cfg.DenyPorts {
		p.denyPorts[port] = struct{}{}
	}
	if p.ownAddrsFn == nil {
		p.ownAddrsFn = interfaceAddrs
	}
	return p
}

// Check returns nil when dst may be dialled.
func (p *Policy) Check(dst netip.AddrPort) error {
	addr := dst.Addr().Unmap()
	if !addr.Is4() {
		return &PolicyError{Dst: dst, Reason: "not IPv4"}
	}
	if dst.Port() == 0 {
		return &PolicyError{Dst: dst, Reason: "port 0"}
	}
	if addr.IsUnspecified() {
		return &PolicyError{Dst: dst, Reason: "unspecified address"}
	}
	if _, denied := p.denyPorts[dst.Port()]; denied {
		return &PolicyError{Dst: dst, Reason: fmt.Sprintf("port %d on deny-list", dst.Port())}
	}
	for _, pfx := range p.denyPrefixes {
		if pfx.Contains(addr) {
			return &PolicyError{Dst: dst, Reason: fmt.Sprintf("in denied prefix %s", pfx)}
		}
	}
	if p.isOwnAddr(addr) {
		return &PolicyError{Dst: dst, Reason: "relay's own address"}
	}
	return nil
}

// IsOwnAddr reports whether addr is currently assigned to this host.
func (p *Policy) IsOwnAddr(addr netip.Addr) bool {
	return p.isOwnAddr(addr.Unmap())
}

func (p *Policy) isOwnAddr(addr netip.Addr) bool {
	p.ownMu.Lock()
	defer p.ownMu.Unlock()
	if p.ownAddrs == nil || time.Since(p.ownAddrsRefresh) > p.ownAddrsTTL {
		addrs, err := p.ownAddrsFn()
		if err == nil {
			m := make(map[netip.Addr]struct{}, len(addrs))
			for _, a := range addrs {
				m[a.Unmap()] = struct{}{}
			}
			p.ownAddrs = m
			p.ownAddrsRefresh = time.Now()
		} else if p.ownAddrs == nil {
			// Never fail open: an unknown own-address set denies nothing
			// extra, but the caller still gets the static deny-list.
			p.ownAddrs = map[netip.Addr]struct{}{}
		}
	}
	_, own := p.ownAddrs[addr]
	return own
}

// String renders the deny-list for the startup log.
func (p *Policy) String() string {
	parts := make([]string, 0, len(p.denyPrefixes)+len(p.denyPorts))
	for _, pfx := range p.denyPrefixes {
		parts = append(parts, pfx.String())
	}
	ports := make([]int, 0, len(p.denyPorts))
	for port := range p.denyPorts {
		ports = append(ports, int(port))
	}
	sort.Ints(ports)
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("port/%d", port))
	}
	return strings.Join(parts, ",")
}

func interfaceAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}
