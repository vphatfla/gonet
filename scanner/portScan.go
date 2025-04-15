package scanner

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	routeInfo "github.com/vphatfla/gonet/routing"
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
    // expected IP flow for the returning packet
    // return packet's source IP must be the sending packet's dst IP
    expectIPFlow := gopacket.NewFlow(layers.EndpointIPv4, s.DstIP, s.SrcIP)
    start := time.Now()
    if err := s.Send(s.Eth, s.IPv4, s.TCP); err != nil {
        return nil, err
    }
    for {
        // wait 1 seconds
        if time.Since(start) > time.Second {
            return &PortResult{Status: "Filtered (firewall, blocked)", Port: port, Duration: 0} , nil
        }

        data, _, err := s.Handle.ReadPacketData()
        if err != nil {
            return nil, err
        }

        packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

        ipLayer := packet.NetworkLayer()
        if ipLayer == nil {
            continue
        }
        if ipLayer.NetworkFlow() != expectIPFlow {
            continue
        }

        // diff := cmp.Diff(ipLayer.NetworkFlow(), expectIPFlow, cmp.AllowUnexported(gopacket.Flow{}), cmpopts.EquateComparable())
        //log.Printf("diff = %v", diff)

        tcpLayer := packet.Layer(layers.LayerTypeTCP)
        //log.Printf("TCP Layer = %v", tcpLayer)
        if tcpLayer == nil {
            continue
            // return nil, log.Errorf("No TCP/transport layer in the returning packet")
        }

        d := time.Now().Sub(start)

        tcpSegment, _ := tcpLayer.(*layers.TCP)
        if tcpSegment.RST {
            return &PortResult{Status: "CLOSED (RST)", Port: port, Duration: d} , nil
        } else if tcpSegment.SYN && tcpSegment.ACK {
            return &PortResult{Status: "OPEN (SYN & ACK)", Port: port, Duration:  d}, nil
        } else {
            return &PortResult{Status: "UNKNOWN", Port: port, Duration: d}, nil
        }
    }
}

// scan ports in range
func (s *Scanner) scanRangePorts(ch chan *PortResult, start, end layers.TCPPort) {
    if end > 1023 {
        end = 1023
    }
    for p:= start; p < end; p+=1 {
        r, _ := s.ScanSinglePort(p)
        ch <- r
    }
}
// scan all well-known port from 0 to 1023
func ScanWellKnownPorts(ri *routeInfo.RouteInfo) ([]string, error) {
    var wg sync.WaitGroup
    ch := make(chan *PortResult, 1025)
    res:= make([]string, 1025)

    start := 0
    for start <= 1023 {
        s, err := NewScanner(ri, layers.TCPPort(3000+start))
        if err != nil {
            return nil, err
        }
        wg.Add(1)
        go func(start int, s *Scanner) {
            defer wg.Done()
            /*if err != nil {
                return nil, err
            }*/
            s.scanRangePorts(ch, layers.TCPPort(start), layers.TCPPort(start + 300))
        }(start, s)
        start += 300
    }

    go func() {
        wg.Wait()
        close(ch)
    }()
    for {
        r, ok := <- ch
        if !ok {
            break
        }
        log.Printf("r-> %v", r.ToString())
        res[r.Port] = r.ToString()
    }
    return res, nil
}

// scan all well-known port 0-1023 one thread
func (s *Scanner) ScanWellKnownPortsSingle(ri *routeInfo.RouteInfo) ([]string) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    expectedIPFlow := gopacket.NewFlow(layers.EndpointIPv4, s.DstIP, s.SrcIP)
    portResults := []*PortResult{}
    res := []string{}

    go func() {
        for {
            select {
                case <- ctx.Done():
                    return
                default:
                //log.Println("Default")
                // start reading packet
                    data, _, err := s.Handle.ReadPacketData()
                    if err != nil {
                        log.Printf("port %v -> %v", s.TCP.DstPort, err)
                    }
                    packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
                    ipLayer := packet.NetworkLayer()

                    if ipLayer == nil || ipLayer.NetworkFlow() != expectedIPFlow {
                        continue
                    }
                    tcpLayer := packet.Layer(layers.LayerTypeTCP)
                    if tcpLayer == nil {
                        continue
                    }

                    tcpSegment, _ := tcpLayer.(*layers.TCP)

                    if tcpSegment.RST {
                        portResults = append(portResults, &PortResult{Port: tcpSegment.SrcPort, Status: "CLOSED", Duration: 0})
                    } else if tcpSegment.SYN && tcpSegment.ACK {
                        portResults = append(portResults, &PortResult{Port: tcpSegment.SrcPort, Status: "OPEN", Duration: 0})
                    }
            }
        }
    }()

    start := time.Now()
    s.TCP.DstPort = layers.TCPPort(0)
    for {
        if  s.TCP.DstPort <= 1023 {
            //log.Printf("Port %v ", s.TCP.DstPort)
            err := s.Send(s.Eth, s.IPv4, s.TCP)
            s.TCP.DstPort += 1
            if err != nil {
                log.Printf("port %v -> %v", s.TCP.DstPort, err)
                continue
            }
        }
        if time.Since(start) > time.Second*3 {
            log.Println("Timeout after 3 seconds")
            break
        }
    }
    log.Println("Processing result")
    for _, pr := range portResults {
        res = append(res, pr.ToString())
    }
    //log.Println("Dont processing result")
    return res
}
