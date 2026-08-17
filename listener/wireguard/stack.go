package wireguard

import (
	wireguard "github.com/metacubex/sing-wireguard"
	"github.com/metacubex/wireguard-go/tun"
)

// stackForwardDevice is the tun.Device handed to wireguard-go, extended with the
// ability to forward the decapsulated traffic to a handler.
//
// sing-wireguard's NewStackDevice returns *StackDevice with the with_gvisor build
// tag and the Device interface without it, so the concrete result cannot be used
// directly here; this interface unifies both.
type stackForwardDevice interface {
	tun.Device
	wireguard.RegisterForward
}
