package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"

	C "github.com/metacubex/mihomo/constant"

	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/wireguard-go/conn"
)

var _ conn.Bind = (*serverBind)(nil)

// serverBind is a conn.Bind that listens on a single UDP socket and treats the
// source address of every incoming datagram as a peer endpoint. Unlike ClientBind
// (used by the wireguard outbound) it never dials out, so the same socket serves
// every peer and the wireguard-go device learns each peer's endpoint from its
// handshake.
//
// The socket is created lazily inside Open and torn down in Close, matching the
// lifecycle wireguard-go expects (BindUpdate calls Close then Open, and blocks in
// Close until the receive routine has stopped). It is created through the inbound
// listen config so that listen address and routing-mark behavior stay aligned with
// the other inbound listeners.
type serverBind struct {
	listenConfig C.InboundListenConfig
	network      string
	address      string

	mu   sync.Mutex
	conn net.PacketConn
}

func newServerBind(lc C.InboundListenConfig, network, address string) *serverBind {
	return &serverBind{
		listenConfig: lc,
		network:      network,
		address:      address,
	}
}

func (b *serverBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// The requested port is ignored: the bind address (including its port, or :0
	// for an ephemeral port) already comes from the inbound listen config.
	pc, err := b.listenConfig.ListenPacket(context.Background(), b.network, b.address)
	if err != nil {
		return nil, 0, err
	}
	b.conn = pc
	if udpAddr, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		actualPort = uint16(udpAddr.Port)
	}
	// Capture pc in the receive closure to keep the hot path lock-free.
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := pc.ReadFrom(packets[0])
		if err != nil {
			// Returning the error lets wireguard-go's receive loop stop cleanly on
			// net.ErrClosed (Close) and retry on transient errors.
			return 0, err
		}
		sizes[0] = n
		// normalize 4-in-6 addresses so a peer keeps a single stable endpoint key.
		ap := M.AddrPortFromNet(addr)
		eps[0] = wireguard.Endpoint(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, actualPort, nil
}

func (b *serverBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	pc := b.conn
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	destination := netip.AddrPort(ep.(wireguard.Endpoint))
	udpAddr := net.UDPAddrFromAddrPort(destination)
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, udpAddr); err != nil {
			return err
		}
	}
	return nil
}

func (b *serverBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return wireguard.Endpoint(ap), nil
}

func (b *serverBind) SetMark(mark uint32) error {
	return nil
}

func (b *serverBind) BatchSize() int {
	return 1
}

func (b *serverBind) Close() error {
	b.mu.Lock()
	pc := b.conn
	b.conn = nil
	b.mu.Unlock()
	if pc != nil {
		return pc.Close()
	}
	return nil
}

// LocalAddr reports the address the underlying socket is bound to, or nil if the
// bind is not currently open.
func (b *serverBind) LocalAddr() net.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	return b.conn.LocalAddr()
}
