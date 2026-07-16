//go:build with_gvisor

package wireguard

import (
	"context"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/metacubex/sing/common/buf"
	wgTun "github.com/metacubex/wireguard-go/tun"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

// This file mirrors sing-wireguard's StackDevice, but builds the gVisor stack with
// HandleLocal=false. sing-wireguard uses HandleLocal=true, which — together with
// the promiscuous mode required for forwarding — makes gVisor treat every peer
// source address as a local (temporary) address and drop all inbound packets. Only
// the pieces needed for a forwarding server are kept (no outbound Dial/ListenPacket).

const defaultNIC tcpip.NICID = 1

var _ stackForwardDevice = (*stackDevice)(nil)

type stackDevice struct {
	stack      *stack.Stack
	mtu        uint32
	events     chan wgTun.Event
	outbound   chan *stack.PacketBuffer
	ctx        context.Context
	ctxCancel  context.CancelFunc
	closeOnce  sync.Once
	mu         sync.RWMutex // mu guards dispatcher
	dispatcher stack.NetworkDispatcher
	addr4      tcpip.Address
	addr6      tcpip.Address
}

func newStackForwardDevice(localAddresses []netip.Prefix, mtu uint32) (stackForwardDevice, error) {
	ipStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false, // forwarding server: never treat peer source addresses as our own
	})
	ctx, cancel := context.WithCancel(context.Background())
	tunDevice := &stackDevice{
		stack:     ipStack,
		mtu:       mtu,
		events:    make(chan wgTun.Event, 1),
		outbound:  make(chan *stack.PacketBuffer, 256),
		ctx:       ctx,
		ctxCancel: cancel,
	}
	err := ipStack.CreateNIC(defaultNIC, (*wireEndpoint)(tunDevice))
	if err != nil {
		cancel()
		return nil, E.New(err.String())
	}
	for _, prefix := range localAddresses {
		addr := addressFromAddr(prefix.Addr())
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is4() {
			tunDevice.addr4 = addr
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			tunDevice.addr6 = addr
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		err = ipStack.AddProtocolAddress(defaultNIC, protoAddr, stack.AddressProperties{})
		if err != nil {
			cancel()
			return nil, E.New("parse local address ", protoAddr.AddressWithPrefix, ": ", err.String())
		}
	}
	// Match sing-tun's gVisor stack tuning. Without the explicit buffer ranges and
	// receive-buffer auto-tuning, throughput collapses / stalls under simultaneous
	// bidirectional load (e.g. HTTP/2 over TLS).
	const bufSize = 20 * 1024
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	cOpt := tcpip.CongestionControlOption("cubic")
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	ipStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: defaultNIC})
	ipStack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: defaultNIC})
	return tunDevice, nil
}

func (w *stackDevice) RegisterForward(handler forwardHandler) error {
	ctx := w.ctx
	ipStack := w.stack
	s := &stackForwarder{ctx: ctx, stack: ipStack, handler: handler}
	ipStack.SetSpoofing(defaultNIC, true)        // allow sending any SrcIP (return traffic)
	ipStack.SetPromiscuousMode(defaultNIC, true) // allow receiving any DstIP
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(ipStack, 0, 1024, s.tcpForward).HandlePacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, s.udpForward)
	return nil
}

func (w *stackDevice) File() *os.File {
	return nil
}

func (w *stackDevice) Read(bufs [][]byte, sizes []int, offset int) (count int, err error) {
	select {
	case packetBuffer, ok := <-w.outbound:
		if !ok {
			return 0, os.ErrClosed
		}
		defer packetBuffer.DecRef()
		p := bufs[0]
		p = p[offset:]
		n := 0
		for _, slice := range packetBuffer.AsSlices() {
			n += copy(p[n:], slice)
		}
		sizes[0] = n
		count = 1
		return
	case <-w.ctx.Done():
		return 0, os.ErrClosed
	}
}

func (w *stackDevice) Write(bufs [][]byte, offset int) (count int, err error) {
	for _, b := range bufs {
		b = b[offset:]
		if len(b) == 0 {
			continue
		}
		w.mu.RLock()
		dispatcher := w.dispatcher
		w.mu.RUnlock()
		if dispatcher == nil {
			err = os.ErrClosed
			return
		}
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(b) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		default:
			// WireGuard only authenticates the sender; a peer can still emit
			// frames that are not valid IP packets. Drop them instead of
			// delivering them with a zero protocol number.
			continue
		}
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(b),
		})
		dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
		packetBuffer.DecRef()
		count++
	}
	return
}

func (w *stackDevice) Flush() error {
	return nil
}

func (w *stackDevice) MTU() (int, error) {
	return int(w.mtu), nil
}

func (w *stackDevice) Name() (string, error) {
	return "mihomo-wireguard", nil
}

func (w *stackDevice) Events() <-chan wgTun.Event {
	return w.events
}

func (w *stackDevice) Close() error {
	w.closeOnce.Do(func() {
		w.ctxCancel()
		close(w.events)
		w.stack.Close()
		for _, endpoint := range w.stack.CleanupEndpoints() {
			endpoint.Abort()
		}
		w.stack.Wait()
		// After stack.Wait() no WritePackets sender remains and Read has
		// stopped consuming (ctx is canceled), so release any packets still
		// queued in outbound.
		for {
			select {
			case packetBuffer := <-w.outbound:
				packetBuffer.DecRef()
			default:
				return
			}
		}
	})
	return nil
}

func (w *stackDevice) BatchSize() int {
	return 1
}

var _ stack.LinkEndpoint = (*wireEndpoint)(nil)

type wireEndpoint stackDevice

func (ep *wireEndpoint) MTU() uint32 {
	return ep.mtu
}

func (ep *wireEndpoint) SetMTU(mtu uint32) {
}

func (ep *wireEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *wireEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *wireEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
}

func (ep *wireEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *wireEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.dispatcher = dispatcher
}

func (ep *wireEndpoint) IsAttached() bool {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.dispatcher != nil
}

func (ep *wireEndpoint) Wait() {
}

func (ep *wireEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *wireEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

func (ep *wireEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (ep *wireEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		// IncRef must happen before the channel send: once queued, Read may
		// consume and DecRef the buffer at any moment.
		packetBuffer.IncRef()
		select {
		case <-ep.ctx.Done():
			packetBuffer.DecRef()
			return 0, &tcpip.ErrClosedForSend{}
		case ep.outbound <- packetBuffer:
		}
	}
	return list.Len(), nil
}

func (ep *wireEndpoint) Close() {
}

func (ep *wireEndpoint) SetOnCloseAction(f func()) {
}

type stackForwarder struct {
	ctx     context.Context
	stack   *stack.Stack
	handler forwardHandler
}

func (w *stackForwarder) tcpForward(r *tcp.ForwarderRequest) {
	var wq waiter.Queue
	handshakeCtx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-w.ctx.Done():
			wq.Notify(wq.Events())
		case <-handshakeCtx.Done():
		}
	}()
	endpoint, err := r.CreateEndpoint(&wq)
	cancel()
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	endpoint.SocketOptions().SetKeepAlive(true)
	keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveIdle)
	keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveInterval)
	tcpConn := gonet.NewTCPConn(&wq, endpoint)
	lAddr := tcpConn.RemoteAddr()
	rAddr := tcpConn.LocalAddr()
	if lAddr == nil || rAddr == nil {
		tcpConn.Close()
		return
	}
	go func() {
		var metadata M.Metadata
		metadata.Source = M.SocksaddrFromNet(lAddr)
		metadata.Destination = M.SocksaddrFromNet(rAddr)
		hErr := w.handler.NewConnection(w.ctx, tcpConn, metadata)
		if hErr != nil {
			endpoint.Abort()
		}
	}()
}

func (w *stackForwarder) udpForward(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	var upstreamMetadata M.Metadata
	upstreamMetadata.Source = M.SocksaddrFrom(addrFromAddress(id.RemoteAddress), id.RemotePort)
	upstreamMetadata.Destination = M.SocksaddrFrom(addrFromAddress(id.LocalAddress), id.LocalPort)
	proto := header.IPv6ProtocolNumber
	if upstreamMetadata.Source.IsIPv4() {
		proto = header.IPv4ProtocolNumber
	}
	gBuffer := pkt.Data().ToBuffer()
	sBuffer := buf.NewSize(int(gBuffer.Size()))
	gBuffer.Apply(func(view *buffer.View) {
		sBuffer.Write(view.AsSlice())
	})
	w.handler.NewPacket(
		w.ctx,
		upstreamMetadata.Source.AddrPort(),
		sBuffer,
		upstreamMetadata,
		func(natConn N.PacketConn) N.PacketWriter {
			return &udpBackWriter{
				stack:         w.stack,
				source:        id.RemoteAddress,
				sourcePort:    id.RemotePort,
				sourceNetwork: proto,
			}
		},
	)
	return true
}

type udpBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	source        tcpip.Address
	sourcePort    uint16
	sourceNetwork tcpip.NetworkProtocolNumber
}

func (w *udpBackWriter) WritePacket(packetBuffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	} else if destination.IsIPv4() && w.sourceNetwork == header.IPv6ProtocolNumber {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	} else if destination.IsIPv6() && (w.sourceNetwork == header.IPv4ProtocolNumber) {
		return E.New("send IPv6 packet to IPv4 connection")
	}

	defer packetBuffer.Release()

	route, err := w.stack.FindRoute(
		defaultNIC,
		addressFromAddr(destination.Addr),
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(packetBuffer.Bytes()),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.sourcePort,
		Length:  pLen,
	})

	if route.RequiresTXTransportChecksum() && w.sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	err = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)
	if err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return gonet.TranslateNetstackError(err)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return nil
}

func addressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	}
	return tcpip.AddrFrom4(destination.As4())
}

func addrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	}
	return netip.AddrFrom4(address.As4())
}
