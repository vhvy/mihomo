package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/wireguard"
	"github.com/metacubex/mihomo/log"
)

type WireGuardOption struct {
	BaseOption
	PrivateKey string          `inbound:"private-key"`
	IP         string          `inbound:"ip,omitempty"`
	IPv6       string          `inbound:"ipv6,omitempty"`
	MTU        int             `inbound:"mtu,omitempty"`
	Workers    int             `inbound:"workers,omitempty"`
	Peers      []WireGuardPeer `inbound:"peers,omitempty"`
}

type WireGuardPeer struct {
	PublicKey    string   `inbound:"public-key"`
	PreSharedKey string   `inbound:"pre-shared-key,omitempty"`
	AllowedIPs   []string `inbound:"allowed-ips,omitempty"`
}

func (o WireGuardOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type WireGuard struct {
	*Base
	config *WireGuardOption
	l      *wireguard.Listener
	ws     LC.WireGuardServer
}

func NewWireGuard(options *WireGuardOption) (*WireGuard, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	peers := make([]LC.WireGuardServerPeer, len(options.Peers))
	for i, peer := range options.Peers {
		peers[i] = LC.WireGuardServerPeer{
			PublicKey:    peer.PublicKey,
			PreSharedKey: peer.PreSharedKey,
			AllowedIPs:   peer.AllowedIPs,
		}
	}
	return &WireGuard{
		Base:   base,
		config: options,
		ws: LC.WireGuardServer{
			Enable:     true,
			Listen:     base.RawAddress(),
			PrivateKey: options.PrivateKey,
			IP:         options.IP,
			IPv6:       options.IPv6,
			MTU:        options.MTU,
			Workers:    options.Workers,
			Peers:      peers,
		},
	}, nil
}

// Config implements constant.InboundListener
func (w *WireGuard) Config() C.InboundConfig {
	return w.config
}

// Address implements constant.InboundListener
func (w *WireGuard) Address() string {
	var addrList []string
	if w.l != nil {
		for _, addr := range w.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (w *WireGuard) Listen(tunnel C.Tunnel) error {
	var err error
	w.l, err = wireguard.New(w.ws, w.ListenConfig(), tunnel, w.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("WireGuard[%s] proxy listening at: %s", w.Name(), w.Address())
	return nil
}

// Close implements constant.InboundListener
func (w *WireGuard) Close() error {
	if w.l != nil {
		return w.l.Close()
	}
	return nil
}

var _ C.InboundListener = (*WireGuard)(nil)
