package wireguard

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/wireguard-go/tun"
)

// forwardHandler receives the TCP connections and UDP packets that the gVisor
// stack extracts from the WireGuard tunnel. *sing.ListenerHandler satisfies it,
// so incoming traffic is handed to the tunnel/rule engine exactly like the other
// inbound listeners, carrying the real client tunnel address as the source (no NAT).
type forwardHandler interface {
	NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error
	NewPacket(ctx context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) N.PacketWriter)
}

// stackForwardDevice is the tun.Device handed to wireguard-go, extended with the
// ability to forward the decapsulated traffic to a handler.
//
// It intentionally does not reuse sing-wireguard's StackDevice: that device builds
// its gVisor stack with HandleLocal=true, which (together with the promiscuous mode
// required for forwarding) makes gVisor treat every peer source address as one of
// its own and drop all inbound packets. Our stack is built with HandleLocal=false.
type stackForwardDevice interface {
	tun.Device
	RegisterForward(handler forwardHandler) error
}
