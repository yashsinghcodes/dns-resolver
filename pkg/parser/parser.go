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
	Name   []byte
	Type_  uint16
	Class_ uint16
	Ttl_   uint32
	Data   []byte
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
	d := make([]byte, 4)
	binary.Read(buf, binary.BigEndian, d)
	data.Type_ = binary.BigEndian.Uint16(d[:2])
	data.Class_ = binary.BigEndian.Uint16(d[2:])
	return data
}

func DecodeName(buf *bytes.Buffer) []byte {
	var parts [][]byte
	for {
		lengthByte := make([]byte, 1)
		_, err := buf.Read(lengthByte)
		if err != nil {
			fmt.Println(err)
		}
		length := lengthByte[0]
		if length == 0 {
			break
		}
		if length&0b1100_0000 != 0 {
			part := DecodeCompressedName(length, buf)
			parts = append(parts, part)
			break
		} else {
			part := make([]byte, length)
			buf.Read(part)
			parts = append(parts, part)
		}
	}
	return bytes.Join(parts, []byte("."))
}

func ParseRecord(buf *bytes.Buffer) DNSRecord {
	name := DecodeName(buf)
	data := make([]byte, 10)
	binary.Read(buf, binary.BigEndian, data)
	var record DNSRecord
	record.Name = name
	record.Type_ = binary.BigEndian.Uint16(data[:2])
	record.Class_ = binary.BigEndian.Uint16(data[2:4])
	record.Ttl_ = binary.BigEndian.Uint32(data[4:8])
	dataLen := binary.BigEndian.Uint16(data[8:10])
	datar := make([]byte, dataLen)
	binary.Read(buf, binary.BigEndian, datar)
	record.Data = datar
	return record
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
	parseRecord := ParseRecord(buf)
	fmt.Println(findata)
	fmt.Println(parserQuestion)
	fmt.Println(parseRecord)
}
