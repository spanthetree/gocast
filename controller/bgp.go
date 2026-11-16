package controller

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	c "github.com/mayuresh82/gocast/config"
	api "github.com/osrg/gobgp/api"
	gobgp "github.com/osrg/gobgp/pkg/server"
)

type Route struct {
	Net         *net.IPNet
	Communities []string
}

type Controller struct {
	localAS     int
	localIP     net.IP
	peers       []c.PeerConfig
	communities []string
	origin      uint32
	s           *gobgp.BgpServer
}

func NewController(config c.BgpConfig) (*Controller, error) {
	ctrl := &Controller{}
	var gw net.IP
	var err error

	// Normalize config: peer_ip, peer_ips and peers are merged into one list
	// in that order, entries are de-duplicated by IP, and with no peers
	// configured at all the default gateway is used.
	all := []c.PeerConfig{{PeerIP: config.PeerIP}}
	for _, ip := range config.PeerIPs {
		all = append(all, c.PeerConfig{PeerIP: ip})
	}
	var peers []c.PeerConfig
	seen := make(map[string]bool)
	for _, p := range append(all, config.Peers...) {
		if p.PeerIP == "" || seen[p.PeerIP] {
			continue
		}
		seen[p.PeerIP] = true
		peers = append(peers, p)
	}
	if len(peers) == 0 {
		gw, err = gateway()
		if err != nil {
			return nil, fmt.Errorf("Unable to get gateway ip: %v", err)
		}
		peers = []c.PeerConfig{{PeerIP: gw.String()}}
	}
	for i := range peers {
		if net.ParseIP(peers[i].PeerIP) == nil {
			return nil, fmt.Errorf("Invalid peer ip: %q", peers[i].PeerIP)
		}
		// peers without their own peer_as inherit the top-level one
		if peers[i].PeerAS == 0 {
			peers[i].PeerAS = config.PeerAS
		}
	}

	// Determine local IP
	if config.LocalIP == "" {
		// Use first peer to determine local IP. When peers are reachable via
		// different local interfaces, set local_ip explicitly instead.
		gw, err = via(net.ParseIP(peers[0].PeerIP))
		if err != nil {
			return nil, fmt.Errorf("Unable to get gw ip: %v", err)
		}
		ctrl.localIP, err = localAddress(gw)
		if err != nil {
			return nil, err
		}
	} else {
		ctrl.localIP = net.ParseIP(config.LocalIP)
	}

	ctrl.localAS = config.LocalAS
	ctrl.peers = peers
	ctrl.communities = config.Communities

	switch config.Origin {
	case "igp":
		ctrl.origin = 0
	case "egp":
		ctrl.origin = 1
	case "unknown":
		ctrl.origin = 2
	}

	s := gobgp.NewBgpServer()
	go s.Serve()
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         uint32(config.LocalAS),
			RouterId:   ctrl.localIP.String(),
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	}); err != nil {
		return nil, fmt.Errorf("Unable to start bgp: %v", err)
	}
	ctrl.s = s

	return ctrl, nil
}

func (c *Controller) addPeer(peer *c.PeerConfig) error {
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: peer.PeerIP,
			PeerAs:          uint32(peer.PeerAS),
		},
	}

	// multihop defaults to on for eBGP peers, as before multi-peer support;
	// multi_hop overrides it either way
	multiHop := peer.PeerAS != c.localAS
	if peer.MultiHop != nil {
		multiHop = *peer.MultiHop
	}
	if multiHop {
		n.EbgpMultihop = &api.EbgpMultihop{Enabled: true, MultihopTtl: uint32(255)}
	}

	// Configure MD5 authentication if specified
	md5Password := c.getMD5Password(peer)
	if md5Password != "" {
		n.Conf.AuthPassword = md5Password
	}

	return c.s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: n})
}

// getMD5Password retrieves the MD5 password from config or environment variable
func (c *Controller) getMD5Password(peer *c.PeerConfig) string {
	// Priority 1: Check for environment variable
	if peer.MD5EnvVar != "" {
		if password := os.Getenv(peer.MD5EnvVar); password != "" {
			return password
		}
	}

	// Priority 2: Use password from config file
	if peer.MD5Password != "" {
		return peer.MD5Password
	}

	return ""
}

func (c *Controller) getApiPath(route *Route) *api.Path {
	afi := api.Family_AFI_IP
	if route.Net.IP.To4() == nil {
		afi = api.Family_AFI_IP6
	}
	prefixlen, _ := route.Net.Mask.Size()
	nlri, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    route.Net.IP.String(),
		PrefixLen: uint32(prefixlen),
	})
	a1, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: c.origin,
	})
	a2, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: c.localIP.String(),
	})

	// global + per-route communities. Per-peer communities are not possible
	// here: GoBGP keeps one local path per prefix and sends it to every peer.
	var communities []uint32
	for _, comm := range append(append([]string{}, c.communities...), route.Communities...) {
		communities = append(communities, convertCommunity(comm))
	}
	a3, _ := ptypes.MarshalAny(&api.CommunitiesAttribute{
		Communities: communities,
	})
	attrs := []*any.Any{a1, a2, a3}
	return &api.Path{
		Family: &api.Family{Afi: afi, Safi: api.Family_SAFI_UNICAST},
		Nlri:   nlri,
		Pattrs: attrs,
	}
}

// knownPeers returns the neighbor addresses GoBGP currently has configured.
func (c *Controller) knownPeers() (map[string]bool, error) {
	known := make(map[string]bool)
	err := c.s.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
		known[p.Conf.NeighborAddress] = true
	})
	return known, err
}

// Announce adds any missing peers, then adds the route to the local RIB once.
// GoBGP advertises it to every peer. A peer that fails to add does not block
// the announcement to the rest; its error is still returned.
func (c *Controller) Announce(route *Route) error {
	known, err := c.knownPeers()
	if err != nil {
		return err
	}
	var errs []error
	for i := range c.peers {
		peer := &c.peers[i]
		if known[peer.PeerIP] {
			continue
		}
		if err := c.addPeer(peer); err != nil {
			errs = append(errs, fmt.Errorf("peer %s: add error: %v", peer.PeerIP, err))
		}
	}
	if _, err := c.s.AddPath(context.Background(), &api.AddPathRequest{Path: c.getApiPath(route)}); err != nil {
		errs = append(errs, fmt.Errorf("announce error: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("announcement errors: %v", errs)
	}
	return nil
}

// Withdraw removes the route from the local RIB, which withdraws it from
// every peer.
func (c *Controller) Withdraw(route *Route) error {
	return c.s.DeletePath(context.Background(), &api.DeletePathRequest{Path: c.getApiPath(route)})
}

func (c *Controller) PeerInfo() ([]*api.Peer, error) {
	var peers []*api.Peer
	peerMap := make(map[string]bool)

	// Build map of configured peer IPs
	for _, peer := range c.peers {
		peerMap[peer.PeerIP] = true
	}

	// Collect info for all configured peers
	err := c.s.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
		if peerMap[p.Conf.NeighborAddress] {
			peers = append(peers, p)
		}
	})
	if err != nil {
		return nil, err
	}
	return peers, nil
}

// Shutdown shuts down every peer session GoBGP knows about, then stops the
// local BGP server. Peers never added (eg. no route was ever announced) are
// skipped, since ShutdownPeer errors on them. StopBgp always runs.
func (c *Controller) Shutdown() error {
	var errs []error

	known, err := c.knownPeers()
	if err != nil {
		errs = append(errs, fmt.Errorf("list peers error: %v", err))
	}
	for _, peer := range c.peers {
		if !known[peer.PeerIP] {
			continue
		}
		if err := c.s.ShutdownPeer(context.Background(), &api.ShutdownPeerRequest{
			Address: peer.PeerIP,
		}); err != nil {
			errs = append(errs, fmt.Errorf("peer %s: shutdown error: %v", peer.PeerIP, err))
		}
	}

	// Stop BGP server
	if err := c.s.StopBgp(context.Background(), &api.StopBgpRequest{}); err != nil {
		errs = append(errs, fmt.Errorf("stop bgp error: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

func convertCommunity(comm string) uint32 {
	parts := strings.Split(comm, ":")
	first, _ := strconv.ParseUint(parts[0], 10, 32)
	second, _ := strconv.ParseUint(parts[1], 10, 32)
	return uint32(first)<<16 | uint32(second)
}
