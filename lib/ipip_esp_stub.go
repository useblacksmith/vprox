//go:build !linux

package lib

import (
	"errors"
	"net/netip"
)

// The xfrm netlink API only exists on Linux (the netlink package stubs the
// types but not the functions elsewhere), so the ESP install/remove entry
// points are stubbed here to keep native `go test ./lib` working on macOS.
// vprox itself only deploys on linux/amd64.

func (srv *Server) installIpipEsp(clientIP netip.Addr, ifname string, keys ipipEspKeys) error {
	return errors.New("ipip esp requires linux xfrm")
}

func (srv *Server) removeIpipEsp(clientIP netip.Addr) error {
	return nil
}

func (srv *Server) prepareIpipEsp(p *ipipPeer, keys ipipEspKeys) (bool, error) {
	return false, errors.New("ipip esp prepare requires linux xfrm")
}

type ipipEspActivateStatus int

const (
	ipipActivateOk ipipEspActivateStatus = iota
	ipipActivateConflict
	ipipActivateError
)

func (srv *Server) activateIpipEsp(p *ipipPeer, target, expectedActive uint32) (ipipEspActivateStatus, uint32, error) {
	return ipipActivateError, 0, errors.New("ipip esp activate requires linux xfrm")
}

func (srv *Server) outboundIpipEspPolicyReqid(clientIP netip.Addr) (int, bool, error) {
	return 0, false, nil
}

func (srv *Server) ipipHousekeepingLoop() {
	// The vanished-peer half still runs; the ESP half needs xfrm.
	srv.ipipVanishedPeersOnlyLoop()
}
