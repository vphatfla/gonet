package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v3"
)

/*	"bufio"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
	routeInfo "github.com/vphatfla/gonet/routing"
	"github.com/vphatfla/gonet/scanner"*/

func main() {
    cmd := &cli.Command{
        Name: "gonet",
        Usage: "Scan ports status of remote server given its IP Address",
        Action: func(ctx context.Context, c *cli.Command) error {
            fmt.Println("Hello")
            return nil
        },
    }

    if err := cmd.Run(context.Background(), os.Args); err != nil {
        log.Fatal(err)
    }
    /*
    log.Println("Welcome to go net")

    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter IP4 address ")
    input, err := reader.ReadString('\n')
    if err != nil {
        log.Fatal("invalid input : ",err)
    }
    input = input[:len(input)-1]
    ip := net.ParseIP(input).To4()
    if ip == nil {
        fmt.Printf("Input must be an IPv4 addr")
    }
    router, err := routing.New()
    if err != nil {
        log.Fatal(err)
    }

    ri, err := routeInfo.NewRouteInfo(router, ip)
    if err != nil {
        log.Fatal(err)
    }

    s, err := scanner.NewScanner(ri, layers.TCPPort(55555))
    defer s.Close()
    if err != nil {
        log.Fatal(err)
    }

    //log.Print("Start scanning well know ports")
    //res := s.ScanPortsWithRange(ri, layers.TCPPort(0), layers.TCPPort(1023))
    // log.Println("out at main")

    log.Print("Start scanning all port from 0 to 65535")
    res := s.ScanPortsWithRange(ri, layers.TCPPort(0), layers.TCPPort(65535))
    for _, r := range res {
        log.Println(r)
    }
    /*_, err = scanner.ScanWellKnownPorts(ri)
    log.Print("Done")
    if err != nil {
        log.Fatal(err)
    }
    /* for r := range len(res) {
        log.Print(res[r])
    } */

    /* s, err := scanner.NewScanner(ri, layers.TCPPort(55555))
    defer s.Close()
    log.Print("Start scanning")
    pr, err := s.ScanSinglePort(layers.TCPPort(22))
    if err != nil {
        log.Fatal(err)
    }
    log.Print(pr.ToString())

    /* res, err := s.ScanWellKnownPorts()
    if err != nil {
        log.Fatal(err)
    }

    for s := range res {
        log.Println(s)
    }*/
}
