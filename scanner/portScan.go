package scanner

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PortResult struct {
    Port layers.TCPPort
    Status string
    Duration time.Duration
}

func (pr *PortResult) ToString() string {
    return fmt.Sprintf("Port %v status %s ---Scan takes %v", pr.Port, pr.Status, pr.Duration)
}
// scan the particular port specify in args
func (s *Scanner) ScanSinglePort(port layers.TCPPort) (*PortResult, error) {
    s.TCP.DstPort = port

    start := time.Now()

    if err := s.Send(s.Eth, s.IPv4, s.TCP); err != nil {
        return nil, err
    }

    if time.Since(start) > time.Second*3 {
        return &PortResult{Status: "Filtered (firewall, blocked)", Port: port, Duration: 0} , nil
    }

    data, _, err := s.Handle.ReadPacketData()

    if err != nil {
        return nil, err
    }

    packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

    d := time.Now().Sub(start)

    ipLayer := packet.NetworkLayer()
    if ipLayer == nil {
        return nil, fmt.Errorf("No IP/network layer in the returning packet")
    }

    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer == nil {
        return nil, fmt.Errorf("No TCP/transport layer in the returning packet")
    }

    tcpSegment, _ := tcpLayer.(*layers.TCP)
    if tcpSegment.RST {
        return &PortResult{Status: "CLOSED (RST)", Port: port, Duration: d} , nil
    } else if tcpSegment.SYN && tcpSegment.ACK {
        return &PortResult{Status: "OPEN (SYN & ACK)", Port: port, Duration:  d}, nil
    } else {
        return &PortResult{Status: "UNKNOWN", Port: port, Duration: d}, nil
    }
}

// scan all well-known port from 0 to 1023
func (s *Scanner) ScanWellKnownPorts() ([]string, error) {
    ch := make(chan *PortResult)
    res:= make([]string, 1025)
    for p:= 0; p <= 1023; p+=1 {
       go func() {
           r, err := s.ScanSinglePort(layers.TCPPort(p))
           if err != nil || (r != nil && r.Status != "CLOSED (RST)"){
                ch <- r
           }
       }()
    }

    go func() {
        pr := <- ch
        res[pr.Port] = pr.ToString()
    }()

    return res, nil
}
