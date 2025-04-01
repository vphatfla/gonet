package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

type scanner struct {
	// Interface to send packets in 
	iface *net.Interface
	// destination, gateway, source IP address
	dest, gw, src net.IP

	handle *pcap.Handle

	opts gopacket.SerializeOptions
	buf gopacket.SerializeBuffer
}

// return a new scanner for givng IP address
func newScanner(ip net.IP, router routing.Router) (*scanner, error) {
	s := &scanner{
		dest: ip,
		opts: gopacket.SerializeOptions{
			FixLengths: true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	// find the route to the address
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Scanning IP address %v\n", ip)

	s.iface, s.gw, s.src = iface, gw, src

	// open handle for reading/writing packets
	// can att BDF filter 
	handle, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	s.handle = handle

	return s, nil
}

// clean up handle 
func (s *scanner) close() {
	s.handle.Close()
}

// get hardware adddres (MAC) for the packets using ARP request/response

func (s *scanner) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDest := s.dest
	if s.gw != nil {
		arpDest = s.gw
	}

	// prepare layers
	eth := layers.Ethernet{
		SrcMAC: s.iface.HardwareAddr,
		DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// arp packet header
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6,
		ProtAddressSize: 4,
		Operation: layers.ARPRequest,
		SourceHwAddress: []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress: []byte{0,0,0,0,0,0},
		DstProtAddress: []byte(arpDest),
	}

	if err := s.send(&eth, &arp); err != nil {
		return nil, err 	
	}

	// wait 3 sec 
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDest)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

// scan all the ports of the given IP address
func (s *scanner) scan() error {
	// get the mac address
	hwaddr, err := s.getHwAddr()
	if err != nil { 
		return err 
	}

	// construct layers

	eth := layers.Ethernet{
		SrcMAC: s.iface.HardwareAddr,
		DstMAC: hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dest,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 0, // will be incremented during the scan
		SYN:     true,
	}

	tcp.SetNetworkLayerForChecksum(&ip4)

	// flow for returning packets 

	// ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dest, s.src) // reverse since this is for retuning packets

	start := time.Now()

	for {
		if tcp.DstPort < 25 {
            fmt.Printf("Sending packet to %v:%v \n", s.dest, tcp.DstPort)
			start = time.Now()
			tcp.DstPort += 1
			if err := s.send(&eth, &ip4, &tcp); err != nil {
				fmt.Printf("error sending to port %v with err %v \n ", tcp.DstPort, err)
			}
        } else {
            break
        }

		if time.Since(start) > time.Second*5 {
            fmt.Printf("timed out for %v:%v, assuming we've seen all we can", s.dest, tcp.DstPort)
			return nil
		}

		data, _, err := s.handle.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			fmt.Printf("error reading packet: %v", err)
			continue
		}

		// parse the packet data 

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		// check the network layer packet 
        fmt.Printf("packet = %v", packet)
		if net := packet.NetworkLayer(); net == nil {
			fmt.Println("packet has no network layer")
		// } else if net.NetworkFlow() != ipFlow {
		//	fmt.Println("Packet does not match src/dst ip")
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			fmt.Println("packet does not have tcp layer")
		} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
			panic("tcp layer is not a tcp layer ")
		// } else if tcp.DstPort != 54321 {
		//	fmt.Println("incoming packet's dst port is not equal ", tcp.DstPort)
		} else if tcp.RST {
			fmt.Printf(" port %v closed", tcp.SrcPort)
		} else if tcp.SYN && tcp.ACK {
			fmt.Printf(" port %v open", tcp.SrcPort)
		}	
    }
    return nil
}
func main() {
    fmt.Println("Hello ")
    router, err := routing.New()
	if err != nil {
		fmt.Println(err)
		log.Fatal("routing err : ", err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter IP4 address ")
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("invalid input : ",err)
	}
	input = input[:len(input)-1]

	ip := net.ParseIP(input)

	s, err := newScanner(ip, router)

	if err != nil {
		log.Fatal("error creating new scanner ", err)
	}

	if err := s.scan(); err != nil {
		log.Printf("error scanning %v -> %v ", ip, err)
	}

	s.close()
}
