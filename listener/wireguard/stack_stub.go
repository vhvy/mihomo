//go:build !with_gvisor

package wireguard

import (
	"net/netip"

	E "github.com/metacubex/sing/common/exceptions"
)

var errGVisorNotIncluded = E.New(`gVisor is not included in this build, rebuild with -tags with_gvisor`)

func newStackForwardDevice(localPrefixes []netip.Prefix, mtu uint32) (stackForwardDevice, error) {
	return nil, errGVisorNotIncluded
}
