//go:build !linux

package lib

import "net/netip"

// The xfrm netlink API only exists on Linux; vprox itself only deploys on
// linux/amd64. This stub keeps native `go test ./lib` working elsewhere.
func (srv *Server) removeLegacyIpipEsp(clientIP netip.Addr) error {
	return nil
}
