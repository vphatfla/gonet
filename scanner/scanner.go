package scanner

import (
    "fmt"
    "net"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/routing"
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

func NewScanner(router routing.Router, dstIP net.IP, srcPort layers.TCPPort) (*Scanner, error) {
    s := &Scanner{
        DstIP: dstIP,

        Opts: gopacket.SerializeOptions{
            FixLengths: true,
            ComputeChecksums: true,
        },
        Buf: gopacket.NewSerializeBuffer(),
    }

    // routing function
    iface, gw, computedSrcIP, err := router.Route(dstIP)
    if err != nil {
        return nil, err
    }

    s.Iface, s.SrcIP, s.GwDstIP = iface, computedSrcIP, gw

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
    return s, nil
}

func (s *Scanner) Close() {
    s.Handle.Close()
}

func (s *Scanner) Send(l ...gopacket.SerializableLayer) error {
    if err := gopacket.SerializeLayers(s.Buf, s.Opts, l...); err != nil {
        return err
    }

    return s.Handle.WritePacketData(s.Buf.Bytes())
}

// scan the particular port specify in args
func (s *Scanner) ScanSinglePort(port layers.TCPPort) (string, time.Duration, error) {
    start := time.Now()

    if err := s.Send(s.Eth, s.IPv4, s.TCP); err != nil {
        return "", 0, err
    }

    if time.Since(start) > time.Second*3 {
        return "Filtered (firewall, blocked)", 0, nil
    }
    
    data, _, err := s.Handle.ReadPacketData()

    if err != nil {
        return "", 0, err
    }

    packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

    d := time.Now().Sub(start)

    ipLayer := packet.NetworkLayer()
    if ipLayer == nil {
        return "", d, fmt.Errorf("No IP/network layer in the returning packet")
    }
    
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer == nil {
        return "", d, fmt.Errorf("No TCP/transport layer in the returning packet")
    }

    tcpSegment, _ := tcpLayer.(*layers.TCP)
    if tcpSegment.RST {
        return "CLOSED (RST)", d, nil
    } else if tcpSegment.SYN && tcpSegment.ACK {
        return "OPEN (SYN & ACK), d, nil", d, nil
    } else {
        return "UNKNOWN", d, nil
    }
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

    if err := s.Send(&eth, &arp); err != nil {
        return err
    }

    time.Sleep(3*time.Second)

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

    return fmt.Errorf("Error getting initial mac address")
}
