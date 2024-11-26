package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/modal-labs/vprox/lib"
)

const awsPollDuration = 5 * time.Second // AWS is polled this frequently for new IPs

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a VPN server, listening for new WireGuard peers",
	RunE:  runServer,
}

var serverCmdArgs struct {
	ip                  []string
	wgBlock             string
	wgBlockPerIp        string
	cloud               string
	region              string
	internalNetworkCidr string
}

func init() {
	ServerCmd.Flags().StringArrayVar(&serverCmdArgs.ip, "ip",
		[]string{}, "IPv4 address to bind to")
	ServerCmd.Flags().StringVar(&serverCmdArgs.wgBlock, "wg-block",
		"", "Block of IPs for WireGuard peers, must be unique between servers")
	ServerCmd.Flags().StringVar(&serverCmdArgs.wgBlockPerIp, "wg-block-per-ip",
		"", "WireGuard block size for each --ip flag, if multiple are provided")
	ServerCmd.Flags().StringVar(&serverCmdArgs.cloud, "cloud",
		"", "Cloud provider for IP metadata (watches for changes)")
	ServerCmd.Flags().StringVar(&serverCmdArgs.region, "region", "",
		"Region of the server")
	ServerCmd.Flags().StringVar(&serverCmdArgs.internalNetworkCidr, "internal-network-cidr",
		"10.0.0.0/24", "Internal network CIDR to route to")
}

func runServer(cmd *cobra.Command, args []string) error {
	cloud := serverCmdArgs.cloud
	if cloud != "" && cloud != "aws" {
		return fmt.Errorf("unknown value of --cloud: %v", cloud)
	}

	if cloud == "" && len(serverCmdArgs.ip) == 0 {
		return errors.New("missing required flag: --ip")
	}
	if len(serverCmdArgs.ip) > 1024 {
		return errors.New("too many --ip flags")
	}
	if serverCmdArgs.wgBlock == "" {
		return errors.New("missing required flag: --wg-block")
	}
	if serverCmdArgs.region == "" {
		return errors.New("missing required flag: --region")
	}

	wgBlock, err := netip.ParsePrefix(serverCmdArgs.wgBlock)
	if err != nil || !wgBlock.Addr().Is4() {
		return fmt.Errorf("failed to parse --wg-block: %s", serverCmdArgs.wgBlock)
	}
	wgBlock = wgBlock.Masked()

	wgBlockPerIp := uint(wgBlock.Bits())
	if serverCmdArgs.wgBlockPerIp != "" {
		if serverCmdArgs.wgBlockPerIp[0] != '/' {
			return errors.New("--wg-block-per-ip must start with '/'")
		}
		parsedUint, err := strconv.ParseUint(serverCmdArgs.wgBlockPerIp[1:], 10, 0)
		if err != nil {
			return fmt.Errorf("failed to parse --wg-block-per-ip: %v", err)
		}
		wgBlockPerIp = uint(parsedUint)
	}

	if wgBlockPerIp > 30 || wgBlockPerIp < uint(wgBlock.Bits()) {
		return fmt.Errorf("invalid value of --wg-block-per-ip: %v", wgBlockPerIp)
	}
	wgBlockCount := 1 << (wgBlockPerIp - uint(wgBlock.Bits()))
	if len(serverCmdArgs.ip) > wgBlockCount {
		return fmt.Errorf(
			"not enough IPs in --wg-block for %v --ip flags, please set --wg-block-per-ip",
			len(serverCmdArgs.ip))
	}

	key, err := lib.GetServerKey()
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	password, err := lib.GetVproxPassword()
	if err != nil {
		return err
	}

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	sm, err := lib.NewServerManager(wgBlock, wgBlockPerIp, ctx, key, password, serverCmdArgs.region, serverCmdArgs.internalNetworkCidr)
	if err != nil {
		done()
		return err
	}

	defer sm.Wait()
	defer done()

	// Start the liveness reporter.
	livenessReporter := &LivenessReporter{
		client:            http.Client{Timeout: 5 * time.Second},
		ip:                serverCmdArgs.ip[0],
		region:            serverCmdArgs.region,
		backendEndpoint:   os.Getenv("BACKEND_ENDPOINT"),
		backendAdminToken: os.Getenv("BACKEND_ADMIN_TOKEN"),
	}
	livenessReporter.Start(ctx)

	for _, ipStr := range serverCmdArgs.ip {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("invalid IPv4 address: %q", ipStr)
		}
		err = sm.Start(ip)
		if err != nil {
			return err
		}
	}
	sm.Wait()

	return nil
}

type ipSet map[netip.Addr]struct{}

// parseIpSet parses the provided ipStrs and creates a map with
// the parsed IPs that can be used as a set.
func parseIpSet(ipStrs []string) (ipSet, error) {
	m := make(ipSet)
	for _, ipStr := range ipStrs {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address: %v", ipStr)
		}
		m[ip] = struct{}{}
	}
	return m, nil
}
