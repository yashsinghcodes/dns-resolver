package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	q "github.com/yashsinghcodes/dns-resolver/pkg/query"
)

type DNSRecord struct {
	name   []byte
	type_  int
	class_ int
	ttl_   int
	data   []byte
}

func ParseHeader(buf *bytes.Buffer) q.DNSHeader {
	var data q.DNSHeader
	binary.Read(buf, binary.BigEndian, &data)
	return data
}

func ParseQuestion(buf *bytes.Buffer) q.DNSQuestion {
	name := DecodeName(buf)
	var data q.DNSQuestion
	data.Name = name
	binary.Read(buf, binary.BigEndian, &data)
	return data
}

func DecodeName(buf *bytes.Buffer) []byte {
	var name [][]byte
	for {
		lengthByte := make([]byte, 1)
		_, err := buf.Read(lengthByte)
		if err != nil {
			panic("An Error caused in reading")
		}
		length := int(lengthByte[0])
		if length == 0 {
			break
		}
		part := make([]byte, length)
		buf.Read(part)
		name = append(name, part)
	}
	return bytes.Join(name, []byte("."))
}

func Testresp() []byte {
	queryy := q.Build_query("www.example.com", 1, 1, 1)
	addr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return nil
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return nil
	}
	_, err = conn.Write(queryy)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return nil
	}
	res := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(res)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error in connecting")
		return nil
	}
	return res[:n]
}

func main() {
	// sample response for now
	myBytes := Testresp()
	buf := bytes.NewBuffer(myBytes)
	findata := ParseHeader(buf)
	parserQuestion := ParseQuestion(buf)
	fmt.Println(findata)
	fmt.Println(parserQuestion)
}
