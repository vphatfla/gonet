package scanner

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	routeInfo "github.com/vphatfla/gonet/routing"
)

type Scanner struct {
    // interface to send packets in
    Iface *net.Interface

    DstIP, SrcIP, GwDstIP net.IP

    InitialDstMACAddrr net.HardwareAddr

    Handle *pcap.Handle

    Opts gopacket.SerializeOptions
    Buf gopacket.SerializeBuffer

    Eth *layers.Ethernet
    IPv4 *layers.IPv4
    TCP *layers.TCP
}

func NewScanner(ri *routeInfo.RouteInfo, srcPort layers.TCPPort) (*Scanner, error) {
    s := &Scanner{
        DstIP: ri.DstIP,

        Opts: gopacket.SerializeOptions{
            FixLengths: true,
            ComputeChecksums: true,
        },
        Buf: gopacket.NewSerializeBuffer(),
    }

    // routing function
    s.Iface, s.SrcIP, s.GwDstIP = ri.Iface, ri.SrcIP, ri.GwIP

    handle, err := pcap.OpenLive(s.Iface.Name, 65535, true, pcap.BlockForever)
    if err != nil {
        return nil, err
    }

    s.Handle = handle

    if err := s.getInitialDstMacAddr(); err != nil {
        return nil, err
    }

    s.Eth = &layers.Ethernet{
        SrcMAC: s.Iface.HardwareAddr,
        DstMAC: s.InitialDstMACAddrr,
        EthernetType: layers.EthernetTypeIPv4,
    }
    s.IPv4 = &layers.IPv4{
        SrcIP: s.SrcIP,
        DstIP: s.DstIP,
        Version: 4,
        TTL: 64,
        Protocol: layers.IPProtocolTCP,
    }
    s.TCP = &layers.TCP{
        SrcPort: srcPort,
        SYN: true,
    }

    s.TCP.SetNetworkLayerForChecksum(s.IPv4)

    return s, nil
}

func (s *Scanner) Close() {
    log.Println("Closing scanner")
    s.Handle.Close()
}

func (s *Scanner) Send(l ...gopacket.SerializableLayer) error {
    if err := gopacket.SerializeLayers(s.Buf, s.Opts, l...); err != nil {
        return err
    }

    return s.Handle.WritePacketData(s.Buf.Bytes())
}

// get MAC-HardwareAddr of the initial packet to travel to
// this MAC addr is  needed in the ethernet layer configuration
// if you run this on a device at home, this will return your router's MAC addr most of the time
func (s *Scanner) getInitialDstMacAddr() (error) {
    arpDest := s.DstIP
    if s.GwDstIP != nil {
        arpDest = s.GwDstIP
    }

    eth := layers.Ethernet{
        SrcMAC: s.Iface.HardwareAddr,
        DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        EthernetType: layers.EthernetTypeARP,
    }

    arp := layers.ARP{
        AddrType: layers.LinkTypeEthernet,
        Protocol: layers.EthernetTypeIPv4,
        HwAddressSize: 6,
        ProtAddressSize: 4,
        Operation: layers.ARPRequest,
        SourceHwAddress: []byte(s.Iface.HardwareAddr),
        SourceProtAddress: []byte(s.SrcIP),
        DstHwAddress: []byte{0,0,0,0,0,0},
        DstProtAddress: []byte(arpDest),
    }

    start := time.Now()

    if err := s.Send(&eth, &arp); err != nil {
        return err
    }

    for {
        if time.Since(start) > time.Second*3 {
            return fmt.Errorf("time out getting initial  MAC addr")
        }
        data, _, err := s.Handle.ReadPacketData()

        if err != nil {
            return err
        }

        packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

        if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
            arp := arpLayer.(*layers.ARP)
            // make sure that the returning packet's source addr == the sending packet dst addr
            if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDest)) {
                // the sourceHwAddr of the returning packet is the first mac address for the packet in the first hop
                s.InitialDstMACAddrr = net.HardwareAddr(arp.SourceHwAddress)
                return nil
            }
        }
    }
}
