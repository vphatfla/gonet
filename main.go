package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
	routeInfo "github.com/vphatfla/gonet/routing"
	"github.com/vphatfla/gonet/scanner"
)

func main() {
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

    log.Print("Start scanning well know ports")
    s, err := scanner.NewScanner(ri, layers.TCPPort(55555))
    defer s.Close()
    if err != nil {
        log.Fatal(err)
    }
    res := s.ScanWellKnownPortsSingle(ri)
   
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
