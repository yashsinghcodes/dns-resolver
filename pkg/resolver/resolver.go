package main

import (
	"fmt"
	"net"
	"os"

	p "github.com/yashsinghcodes/dns-resolver/pkg/parser"
	q "github.com/yashsinghcodes/dns-resolver/pkg/query"
)

func SendQuery(ipAddr string, domainName string, recordType uint16) p.DNSPacket {
	queryy := q.Build_query(domainName, recordType, 1)
	addr, err := net.ResolveUDPAddr("udp", ipAddr)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return p.DNSPacket{}
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return p.DNSPacket{}
	}
	_, err = conn.Write(queryy)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return p.DNSPacket{}
	}
	res := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(res)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return p.DNSPacket{}
	}
	return p.ParsePacket(res[:n])
}

func ip_string(dat []byte) string {
	a := fmt.Sprintf("%s", dat)
	return a
}

func ipToString(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func main() {
	m := SendQuery("216.239.32.10:53", "google.com", 1)
	fmt.Println(p.ParseIP((m.Answer[0].Data)))
}
