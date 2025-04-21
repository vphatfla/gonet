package routeInfo

import (
	"fmt"
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
    IPVersion int16
}

func NewRouteInfo(router routing.Router, dstIP net.IP) (*RouteInfo, error) {
    var finalDstIP net.IP
    var version int16
    if dstIP.To4() != nil {
        finalDstIP = dstIP.To4()
        version = int16(4)
    } else if dstIP.To16() != nil {
        finalDstIP = dstIP.To16()
        version = int16(6)
    } else {
        return nil, fmt.Errorf("IP Addr not valid : %v", dstIP)
    }
    fmt.Println(finalDstIP.To16())
    fmt.Printf("Final dstIP = %v with version = %v", finalDstIP, version)
    iface, gwIP, srcIP, err := router.Route(finalDstIP)
    if err != nil {
        return nil, err
    }
    return &RouteInfo{
        Iface: iface,
        GwIP: gwIP,
        SrcIP: srcIP,
        DstIP: finalDstIP,
        IPVersion: version,
    }, nil
}
