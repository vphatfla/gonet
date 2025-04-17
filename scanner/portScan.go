package scanner

import (
	"context"
	"fmt"
	"log"
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

// General function to scan multiple port range from start to end inclusively
func (s *Scanner) ScanPortsWithRange(ri *routeInfo.RouteInfo, start, end layers.TCPPort) ([]string) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    expectedIPFlow := gopacket.NewFlow(layers.EndpointIPv4, s.DstIP, s.SrcIP)
    portResults := []*PortResult{}
    res := []string{}
    durationMap := make(map[layers.TCPPort]time.Time)

    go func(durationMap *map[layers.TCPPort]time.Time) {
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

                    var duration time.Duration
                    if start, ok := (*durationMap)[tcpSegment.SrcPort]; !ok {
                        duration = -1
                    } else {
                        duration = time.Since(start)
                    }

                    if tcpSegment.RST {
                        portResults = append(portResults, &PortResult{Port: tcpSegment.SrcPort, Status: "CLOSED", Duration: duration})
                    } else if tcpSegment.SYN && tcpSegment.ACK {
                        portResults = append(portResults, &PortResult{Port: tcpSegment.SrcPort, Status: "OPEN", Duration: duration})
                    }
            }
        }
    }(&durationMap)

    startTime := time.Now()
    s.TCP.DstPort = start
    for {
        if  s.TCP.DstPort <= end {
            durationMap[s.TCP.DstPort] = time.Now()
            err := s.Send(s.Eth, s.IPv4, s.TCP)
            s.TCP.DstPort += 1
            if err != nil {
                log.Printf("port %v -> %v", s.TCP.DstPort, err)
                continue
            }
        }
        if time.Since(startTime) > time.Second*3 {
            log.Println("Timeout after 3 seconds")
            break
        }
    }
    // log.Println("Processing result")
    for _, pr := range portResults {
        res = append(res, pr.ToString())
    }
    //log.Println("Dont processing result")
    return res
}
