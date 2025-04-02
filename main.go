package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
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

    ip := net.ParseIP(input)

    router, err := routing.New()
    if err != nil {
        log.Fatal(err)
    }

    s, err := scanner.NewScanner(router, ip, layers.TCPPort(55555))
    defer s.Close()

    m, d, err := s.ScanSinglePort(layers.TCPPort(22))
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Port 22 -> %v \nScan takes %v", m, d)
}
