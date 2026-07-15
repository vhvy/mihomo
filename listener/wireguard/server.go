package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/wireguard-go/device"
)

// defaultMTU matches the value used by the wireguard outbound.
const defaultMTU = 1408

type Listener struct {
	closed     bool
	config     LC.WireGuardServer
	binds      []*serverBind
	devices    []*device.Device
	tunDevices []stackForwardDevice
}

func New(config LC.WireGuardServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-WIREGUARD"),
			inbound.WithSpecialRules(""),
		}
	}

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.WIREGUARD,
		Additions: additions,
	})
	if err != nil {
		return nil, err
	}

	localPrefixes, err := parsePrefixes(config.IP, config.IPv6)
	if err != nil {
		return nil, err
	}

	ipcConf, err := genServerIpcConf(config)
	if err != nil {
		return nil, err
	}

	mtu := config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	sl := &Listener{config: config}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		tunDevice, err := newStackForwardDevice(localPrefixes, uint32(mtu))
		if err != nil {
			_ = sl.Close()
			return nil, E.Cause(err, "create WireGuard device")
		}
		sl.tunDevices = append(sl.tunDevices, tunDevice)

		// The bind creates its UDP socket lazily on Open (i.e. on wgDevice.Up),
		// through the inbound listen config so listen address / routing-mark stay
		// aligned with the other inbound listeners.
		bind := newServerBind(lc, "udp", addr)
		sl.binds = append(sl.binds, bind)

		logger := &device.Logger{
			Verbosef: func(format string, args ...any) {
				log.SingLogger.Debug(fmt.Sprintf("[WG](%s) %s", config.Listen, fmt.Sprintf(format, args...)))
			},
			Errorf: func(format string, args ...any) {
				log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", config.Listen, fmt.Sprintf(format, args...)))
			},
		}
		wgDevice := device.NewDevice(tunDevice, bind, logger, config.Workers)
		sl.devices = append(sl.devices, wgDevice)

		if err = wgDevice.IpcSet(ipcConf); err != nil {
			_ = sl.Close()
			return nil, E.Cause(err, "setup wireguard")
		}

		// register the inbound TCP/UDP forwarder before packets start flowing.
		// *sing.ListenerHandler satisfies forwardHandler, so the real client tunnel
		// address is carried through as the connection source (no NAT), and traffic
		// follows the normal rule engine like other inbounds.
		if err = tunDevice.RegisterForward(h); err != nil {
			_ = sl.Close()
			return nil, E.Cause(err, "register WireGuard forward")
		}

		// Bring the device up synchronously (this opens the bind and binds the
		// socket) so the actual listening address is known once New returns.
		if err = wgDevice.Up(); err != nil {
			_ = sl.Close()
			return nil, E.Cause(err, "start WireGuard device")
		}
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, d := range l.devices {
		d.Close() // also closes the associated bind (and its socket)
	}
	for _, b := range l.binds {
		if err := b.Close(); err != nil {
			retErr = err
		}
	}
	for _, t := range l.tunDevices {
		if err := t.Close(); err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() LC.WireGuardServer {
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, b := range l.binds {
		if addr := b.LocalAddr(); addr != nil {
			addrList = append(addrList, addr)
		}
	}
	return
}

// parsePrefixes parses the server's own tunnel addresses. At least one of ip / ipv6
// must be provided, matching a real WireGuard interface which always has an address.
func parsePrefixes(ip, ipv6 string) ([]netip.Prefix, error) {
	localPrefixes := make([]netip.Prefix, 0, 2)
	if len(ip) > 0 {
		if !strings.Contains(ip, "/") {
			ip = ip + "/32"
		}
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, E.Cause(err, "ip address parse error")
		}
		localPrefixes = append(localPrefixes, prefix)
	}
	if len(ipv6) > 0 {
		if !strings.Contains(ipv6, "/") {
			ipv6 = ipv6 + "/128"
		}
		prefix, err := netip.ParsePrefix(ipv6)
		if err != nil {
			return nil, E.Cause(err, "ipv6 address parse error")
		}
		localPrefixes = append(localPrefixes, prefix)
	}
	if len(localPrefixes) == 0 {
		return nil, E.New("missing local address (ip or ipv6)")
	}
	return localPrefixes, nil
}

// genServerIpcConf builds the wireguard-go UAPI config for a server: the local
// private key plus one section per peer (public key, optional preshared key and
// the peer's allowed-ips, which act as the cryptokey-routing / source-IP filter).
func genServerIpcConf(config LC.WireGuardServer) (string, error) {
	privateKey, err := parseKey(config.PrivateKey)
	if err != nil {
		return "", E.Cause(err, "decode private key")
	}
	if len(config.Peers) == 0 {
		return "", E.New("missing peers")
	}

	var b strings.Builder
	b.WriteString("private_key=" + privateKey + "\n")
	for i, peer := range config.Peers {
		publicKey, err := parseKey(peer.PublicKey)
		if err != nil {
			return "", E.Cause(err, "decode public key for peer ", i)
		}
		b.WriteString("public_key=" + publicKey + "\n")
		if peer.PreSharedKey != "" {
			preSharedKey, err := parseKey(peer.PreSharedKey)
			if err != nil {
				return "", E.Cause(err, "decode pre shared key for peer ", i)
			}
			b.WriteString("preshared_key=" + preSharedKey + "\n")
		}
		if len(peer.AllowedIPs) == 0 {
			return "", E.New("missing allowed_ips for peer ", i)
		}
		for _, allowedIP := range peer.AllowedIPs {
			b.WriteString("allowed_ip=" + allowedIP + "\n")
		}
	}
	return b.String(), nil
}

// parseKey converts a base64-encoded WireGuard key into the hex form expected by
// the wireguard-go UAPI, matching the wireguard outbound.
func parseKey(key string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
