package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	q "github.com/yashsinghcodes/dns-resolver/pkg/query"
)

type DNSRecord struct {
	Name   []byte
	Type_  uint16
	Class_ uint16
	Ttl_   uint32
	Data   []byte
}

type DNSPacket struct {
	Header      q.DNSHeader
	Question    []q.DNSQuestion
	Answer      []DNSRecord
	Authorities []DNSRecord
	Additionals []DNSRecord
}

func ParseHeader(buf io.Reader) q.DNSHeader {
	var data q.DNSHeader
	binary.Read(buf, binary.BigEndian, &data)
	return data
}

func ParseQuestion(buf io.Reader) q.DNSQuestion {
	name := DecodeName(buf)
	var data q.DNSQuestion
	data.Name = name
	d := make([]byte, 4)
	binary.Read(buf, binary.BigEndian, d)
	data.Type_ = binary.BigEndian.Uint16(d[0:2])
	data.Class_ = binary.BigEndian.Uint16(d[2:4])
	return data
}

func DecodeName(buf io.Reader) []byte {
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

func DecodeCompressedName(len byte, buf io.Reader) []byte {
	pointerBytes := make([]byte, 2)
	pointerBytes[0] = len & 0b0011_1111
	buf.Read(pointerBytes[1:])
	pointer := binary.BigEndian.Uint16(pointerBytes)
	currentPos, _ := buf.(io.Seeker).Seek(0, io.SeekCurrent)
	buf.(io.Seeker).Seek(int64(pointer), io.SeekStart)
	result := DecodeName(buf)
	buf.(io.Seeker).Seek(currentPos, io.SeekStart)
	return result
}

func ParseRecord(buf io.Reader) DNSRecord {
	name := DecodeName(buf)
	data := make([]byte, 10)
	binary.Read(buf, binary.BigEndian, data)
	var record DNSRecord
	record.Name = name
	record.Type_ = binary.BigEndian.Uint16(data[0:2])
	record.Class_ = binary.BigEndian.Uint16(data[2:4])
	record.Ttl_ = binary.BigEndian.Uint32(data[4:8])
	dataLen := binary.BigEndian.Uint16(data[8:10])
	datar := make([]byte, dataLen)
	binary.Read(buf, binary.BigEndian, datar)
	record.Data = datar
	return record
}

func ParsePacket(myBytes []byte) DNSPacket {
	buf := bytes.NewReader(myBytes)
	header := ParseHeader(buf)

	questions := make([]q.DNSQuestion, header.Num_questions)
	for i := 0; i < int(header.Num_questions); i++ {
		questions[i] = ParseQuestion(buf)
	}

	answers := make([]DNSRecord, header.Num_answers)
	for i := 0; i < int(header.Num_answers); i++ {
		answers[i] = ParseRecord(buf)
	}

	authorities := make([]DNSRecord, header.Num_authorities)
	for i := 0; i < int(header.Num_authorities); i++ {
		authorities[i] = ParseRecord(buf)
	}

	additionals := make([]DNSRecord, header.Num_additionals)
	for i := 0; i < int(header.Num_additionals); i++ {
		additionals[i] = ParseRecord(buf)
	}

	// For CNAME_TYPE
	if answers[0].Type_ == 5 {
		answers = []DNSRecord{answers[len(answers)-1]}
	}

	return DNSPacket{Header: header, Question: questions, Answer: answers, Authorities: authorities, Additionals: additionals}
}

func ParseIP(ip []byte) string {
	return strings.Replace(strings.Replace(strings.Replace(fmt.Sprint(ip), " ", ".", -1), "[", "", -1), "]", "", -1)
}

func Testresp(query string) []byte {
	queryy := q.Build_query(query, 1, 1)
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
	myBytes := Testresp("www.metafilter.com")
	packet := ParsePacket(myBytes)
	fmt.Println(ParseIP(packet.Answer[0].Data))
}
