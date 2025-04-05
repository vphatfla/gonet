package routeInfo

import (
	"net"

	"github.com/google/gopacket/routing"
)

// Routing contains the neccessary network components include
// 1. Iface: device/interface level 2 (Data Link) to send the datagram to.
// 2. Gateway: the gateway IP address to send the packet to (if neccessary)
// 3. Prefered Src IP address (if neccessary)
// This is build on top of gopacket, for linux only
type RouteInfo struct {
    Iface *net.Interface
    GwIP, SrcIP, DstIP net.IP
}

func NewRouteInfo(router routing.Router, dstIP net.IP) (*RouteInfo, error) {
    iface, gwIP, srcIP, err := router.Route(dstIP)
    if err != nil {
        return nil, err
    }
    return &RouteInfo{
        Iface: iface,
        GwIP: gwIP,
        SrcIP: srcIP,
        DstIP: dstIP,
    }, nil
}
