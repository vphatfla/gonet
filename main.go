package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "os"

    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/routing"
    "github.com/urfave/cli/v3"
    "github.com/vphatfla/gonet/routeInfo"
    "github.com/vphatfla/gonet/scanner"
)

func main() {
    var boolInt = map[bool]int{
        true: 1,
        false: 0,
    }

    cmd := &cli.Command{
        Name: "gonet",
        Version: "v0.0.0",
        Copyright: "(c) 2025 vphatfla",
        EnableShellCompletion: true,
        Usage: "Scan ports status of remote server given its IP Address",
        Flags: []cli.Flag{
            &cli.StringFlag{
                Name: "ip",
                Aliases: []string{"i"},
                Usage: "target IP address",
                Required: true,
            },
            &cli.IntSliceFlag{
                Name: "port",
                Aliases: []string{"p"},
                Usage: "scane one or more ports, separated by comma, e.g, '21,80,443,25'",
            },
            &cli.BoolFlag{
                Name: "well-known",
                Aliases: []string{"wkn"},
                Usage: "scan well-known ports (0-1023)",
            },
            &cli.BoolFlag{
                Name: "full",
                Aliases: []string{"a"},
                Usage: "scan all possible port (0-65535)",
            },
        },
        Action: func(ctx context.Context, c *cli.Command) error {
            rawIP := c.String("ip")
            if len(rawIP) == 0 {
                return cli.Exit("IP addr can not be empty", 0)
            }

            dstIP := net.ParseIP(rawIP)

            if dstIP == nil {
                return cli.Exit("Invalid ip addr, must be ipv4 or ipv6", 0)
            }

            router, err := routing.New()
            if err != nil {
                return cli.Exit(err.Error(), 0)
            }

            ri, err := routeInfo.NewRouteInfo(router, dstIP)
            if err != nil {
                return cli.Exit(err.Error(), 0)
            }

            s, err := scanner.NewScanner(ri, layers.TCPPort(54321))
            if err != nil {
                return cli.Exit(err.Error(), 0)
            }

            defer s.Close()
            if boolInt[c.IsSet("port")] + boolInt[c.IsSet("well-known")] + boolInt[c.IsSet("full")] != 1 {
                return cli.Exit("one (and only one) flag allowed between port, well-known, full", 0)
            }

            if c.IsSet("port") {
                fmt.Println("Scanning port(s)")
                ports := c.IntSlice("port")
                for _, p := range ports {
                    pr, err := s.ScanSinglePort(ri, layers.TCPPort(p))
                    if err != nil {
                        fmt.Printf("Scan port %v return error %v \n", pr.Port, err)
                    } else {
                        fmt.Println(pr.ToString())
                    }
                }
                return nil
            }

            if c.IsSet("well-known") {
                fmt.Println("Scanning well-knowns ports [0...1023]")
                prs := s.ScanPortsWithRange(ri, layers.TCPPort(0), layers.TCPPort(1023))
                for _, r := range prs {
                    fmt.Println(r)
                }
                return nil
            }

            if c.IsSet("full") {
                fmt.Println("Scanning all possible ports [0...65535]")
                prs := s.ScanPortsWithRange(ri, layers.TCPPort(0), layers.TCPPort(65535))
                for _, r := range prs {
                    fmt.Println(r)
                }
                return nil
            }

            return nil
        },
    }

    if err := cmd.Run(context.Background(), os.Args); err != nil {
        log.Fatal(err)
    }
}
