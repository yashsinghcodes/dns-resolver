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
	addr, err := net.ResolveUDPAddr("udp", ipAddr+":53")
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

func GetAnswer(packet p.DNSPacket) []byte {
	for _, v := range packet.Answer {
		if v.Type_ == 1 {
			return v.Data
		}
	}
	return []byte{}
}

func GetNameServerIP(packet p.DNSPacket) []byte {
	for _, v := range packet.Additionals {
		if v.Type_ == 1 {
			return (v.Data)
		}
	}
	return []byte{}
}

func GetNameServer(packet p.DNSPacket) string {
	for _, v := range packet.Authorities {
		if v.Type_ == 2 {
			return string(v.Data)
		}
	}
	return ""
}

func Resolve(name string, type_ uint16) []byte {
	rootNameServer := "198.41.0.4"
	for 1 == 1 {
		res := SendQuery(rootNameServer, name, type_)
		ip := GetAnswer(res)
		if len(ip) != 0 {
			return ip
		}
		nsIP := GetNameServerIP(res)
		if string(nsIP) != "" {
			rootNameServer = string(nsIP)
		}
		nsDomain := GetNameServer(res)
		if string(nsIP) == "" {
			rootNameServer = string(Resolve(nsDomain, 1))
		}
	}
	return []byte{}
}
