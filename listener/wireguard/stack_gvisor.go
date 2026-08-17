//go:build with_gvisor

package wireguard

import (
	"net/netip"

	wireguard "github.com/metacubex/sing-wireguard"
)

func newStackForwardDevice(localPrefixes []netip.Prefix, mtu uint32) (stackForwardDevice, error) {
	return wireguard.NewStackDevice(localPrefixes, mtu)
}
