package scanner

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	routeInfo "github.com/vphatfla/gonet/routeInfo"
)

type Scanner struct {
    // interface to send packets in
    iface *net.Interface

    handle *pcap.Handle

    opts gopacket.SerializeOptions
    buf gopacket.SerializeBuffer

    // layers to construct network packets
    eth *layers.Ethernet
    ipv4 *layers.IPv4
    tcp *layers.TCP
}

func NewScanner(ri *routeInfo.RouteInfo, srcPort layers.TCPPort) (*Scanner, error) {
    s := &Scanner{
        opts: gopacket.SerializeOptions{
            FixLengths: true,
            ComputeChecksums: true,
        },
        buf: gopacket.NewSerializeBuffer(),
    }

    s.iface = ri.Iface
    handle, err := pcap.OpenLive(s.iface.Name, 65535, true, pcap.BlockForever)

    if err != nil {
        return nil, err
    }

    s.handle = handle
    initMACAddr, err := s.getInitialDstMacAddr(ri);
    if err != nil {
        return nil, err
    }

    s.eth = &layers.Ethernet{
        SrcMAC: s.iface.HardwareAddr,
        DstMAC: initMACAddr,
        EthernetType: layers.EthernetTypeIPv4,
    }
    s.ipv4 = &layers.IPv4{
        SrcIP: ri.SrcIP,
        DstIP: ri.DstIP,
        Version: 4,
        TTL: 64,
        Protocol: layers.IPProtocolTCP,
    }
    s.tcp = &layers.TCP{
        SrcPort: srcPort,
        SYN: true,
    }

    s.tcp.SetNetworkLayerForChecksum(s.ipv4)

    return s, nil
}

func (s *Scanner) Close() {
    s.handle.Close()
}

func (s *Scanner) SendTCPPort(dstPort layers.TCPPort) error {
    s.tcp.DstPort = dstPort
    return s.send(s.eth, s.ipv4, s.tcp)
}
func (s *Scanner) send(l ...gopacket.SerializableLayer) error {
    if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
        return err
    }

    return s.handle.WritePacketData(s.buf.Bytes())
}

func (s *Scanner) getPacketData() ([]byte, gopacket.CaptureInfo, error) {
    return s.handle.ReadPacketData()
}
// get MAC-HardwareAddr of the initial packet to travel to
// this MAC addr is  needed in the ethernet layer configuration
// if you run this on a device at home, this will return your router's MAC addr most of the time
func (s *Scanner) getInitialDstMacAddr(ri *routeInfo.RouteInfo) (net.HardwareAddr,error) {
    arpDest := ri.DstIP
    if ri.GwIP  != nil {
        arpDest = ri.GwIP
    }

    eth := layers.Ethernet{
        SrcMAC: s.iface.HardwareAddr,
        DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        EthernetType: layers.EthernetTypeARP,
    }

    arp := layers.ARP{
        AddrType: layers.LinkTypeEthernet,
        Protocol: layers.EthernetTypeIPv4,
        HwAddressSize: 6,
        ProtAddressSize: 4,
        Operation: layers.ARPRequest,
        SourceHwAddress: []byte(s.iface.HardwareAddr),
        SourceProtAddress: []byte(ri.SrcIP),
        DstHwAddress: []byte{0,0,0,0,0,0},
        DstProtAddress: []byte(arpDest),
    }

    start := time.Now()

    if err := s.send(&eth, &arp); err != nil {
        return nil, err
    }

    for {
        if time.Since(start) > time.Second*3 {
            return nil, fmt.Errorf("time out getting initial  MAC addr")
        }
        data, _, err := s.handle.ReadPacketData()

        if err != nil {
            return nil, err
        }

        packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

        if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
            arp := arpLayer.(*layers.ARP)
            // make sure that the returning packet's source addr == the sending packet dst addr
            if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDest)) {
                // the sourceHwAddr of the returning packet is the first mac address for the packet in the first hop
                return net.HardwareAddr(arp.SourceHwAddress), nil
            }
        }
    }
}
