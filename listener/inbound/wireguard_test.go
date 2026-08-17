package inbound_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/generator"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func genWireGuardKeyPair(t *testing.T) (privateKey string, publicKey string) {
	t.Helper()
	key, err := generator.GenX25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func genWireGuardPreSharedKey(t *testing.T) string {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(psk)
}

// wireGuardEndToEnd builds a WireGuard inbound (server) and a matching WireGuard
// outbound (client, standing in for a real peer) that dials into it. The returned
// tunnel records the source of every forwarded connection/packet so tests can
// assert the client's real tunnel address is preserved (no NAT). The client tunnel
// address is 10.0.0.2, the server tunnel address is 10.0.0.1.
func wireGuardEndToEnd(t *testing.T, preSharedKey string) (out C.ProxyAdapter, srcOf *sync.Map, cleanup func()) {
	t.Helper()

	serverPrivateKey, serverPublicKey := genWireGuardKeyPair(t)
	clientPrivateKey, clientPublicKey := genWireGuardKeyPair(t)

	const (
		serverTunIP = "10.0.0.1"
		clientTunIP = "10.0.0.2"
	)

	srcOf = &sync.Map{} // network(string) -> source ip(string)

	ctx, cancel := context.WithCancel(context.Background())
	tunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			srcOf.Store("tcp", metadata.SrcIP.String())
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn) // echo
			}()
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			srcOf.Store("udp", metadata.SrcIP.String())
			// echo: reply appears to come from the address the client sent to
			_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr())
			packet.Drop()
		},
		CloseFn:     func() error { cancel(); return nil },
		NewDialerFn: func() C.Dialer { return &TestDialer{dialer: dialer.NewDialer(), ctx: ctx} },
	}

	inboundOptions := inbound.WireGuardOption{
		BaseOption: inbound.BaseOption{
			NameStr: "wireguard_inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		PrivateKey: serverPrivateKey,
		IP:         serverTunIP,
		Peers: []inbound.WireGuardPeer{
			{
				PublicKey:    clientPublicKey,
				PreSharedKey: preSharedKey,
				AllowedIPs:   []string{clientTunIP + "/32"},
			},
		},
	}

	in, err := inbound.NewWireGuard(&inboundOptions)
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))

	addrPort, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)

	outboundOptions := outbound.WireGuardOption{
		Name:       "wireguard_outbound",
		Ip:         clientTunIP,
		PrivateKey: clientPrivateKey,
		UDP:        true,
	}
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.PublicKey = serverPublicKey
	outboundOptions.PreSharedKey = preSharedKey
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err = outbound.NewWireGuard(outboundOptions)
	require.NoError(t, err)

	cleanup = func() {
		_ = out.Close()
		_ = in.Close()
		cancel()
	}
	return out, srcOf, cleanup
}

// testWireGuardTCP dials a TCP connection through the tunnel and exchanges data in
// a ping-pong pattern (half duplex) with the echo server, verifying forwarding and
// that the client's tunnel source address is preserved.
func testWireGuardTCP(t *testing.T, out C.ProxyAdapter, srcOf *sync.Map) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	metadata := &C.Metadata{
		NetWork: C.TCP,
		DstIP:   netip.MustParseAddr("1.2.3.4"),
		DstPort: 12345,
	}
	conn, err := out.DialContext(ctx, metadata)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	payload := make([]byte, 8*1024)
	_, _ = rand.Read(payload)
	buf := make([]byte, len(payload))
	// several half-duplex round trips of increasing size (each chunk stays below the
	// stack buffer sizes so the ping-pong echo can never wedge on a full buffer)
	for _, size := range []int{16, 1500, 4 * 1024, len(payload)} {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload[:size]); !assert.NoError(t, err) {
			return
		}
		if _, err := io.ReadFull(conn, buf[:size]); !assert.NoError(t, err) {
			return
		}
		if !assert.Equal(t, payload[:size], buf[:size]) {
			return
		}
	}

	src, ok := srcOf.Load("tcp")
	assert.True(t, ok, "server should have received a forwarded TCP connection")
	assert.Equal(t, "10.0.0.2", src, "client tunnel source IP must be preserved (no NAT)")
}

// testWireGuardUDP sends a UDP datagram through the tunnel and verifies it is echoed
// back and that the client's tunnel source address is preserved.
func testWireGuardUDP(t *testing.T, out C.ProxyAdapter, srcOf *sync.Map) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dst := netip.MustParseAddr("1.2.3.4")
	metadata := &C.Metadata{
		NetWork: C.UDP,
		DstIP:   dst,
		DstPort: 5353,
	}
	pc, err := out.ListenPacketContext(ctx, metadata)
	if !assert.NoError(t, err) {
		return
	}
	defer pc.Close()

	payload := []byte("hello wireguard udp")
	_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pc.WriteTo(payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 5353))); !assert.NoError(t, err) {
		return
	}
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, payload, buf[:n])

	src, ok := srcOf.Load("udp")
	assert.True(t, ok, "server should have received a forwarded UDP packet")
	assert.Equal(t, "10.0.0.2", src, "client tunnel source IP must be preserved (no NAT)")
}

func testInboundWireGuard(t *testing.T, preSharedKey string) {
	out, srcOf, cleanup := wireGuardEndToEnd(t, preSharedKey)
	defer cleanup()

	t.Run("TCP", func(t *testing.T) { testWireGuardTCP(t, out, srcOf) })
	t.Run("UDP", func(t *testing.T) { testWireGuardUDP(t, out, srcOf) })
}

func TestInboundWireGuard(t *testing.T) {
	if !features.WithGVisor {
		t.Skip("WireGuard inbound requires the with_gvisor build tag")
	}
	t.Run("Plain", func(t *testing.T) {
		testInboundWireGuard(t, "")
	})
	t.Run("PreSharedKey", func(t *testing.T) {
		testInboundWireGuard(t, genWireGuardPreSharedKey(t))
	})
}
