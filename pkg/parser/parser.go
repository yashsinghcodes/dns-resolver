package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

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
		_, _ = buf.Read(lengthByte)
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

func ParseRecord(reader io.Reader) DNSRecord {
	name := DecodeName(reader)
	data := make([]byte, 10)
	binary.Read(reader, binary.BigEndian, data)
	type_, class_, ttl, dataLen := binary.BigEndian.Uint16(data[0:2]), binary.BigEndian.Uint16(data[2:4]), binary.BigEndian.Uint32(data[4:8]), binary.BigEndian.Uint16(data[8:10])

	datar := make([]byte, dataLen)

	if type_ == 1 {
		binary.Read(reader, binary.BigEndian, datar)
		datar = []byte(ParseIP(datar))
	}
	if type_ == 2 {
		datar = DecodeName(reader)
	} else {
		binary.Read(reader, binary.BigEndian, datar)
	}

	return DNSRecord{Name: name, Type_: type_, Class_: class_, Ttl_: ttl, Data: datar}
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
		a := ParseRecord(buf)
		if a.Type_ == 1 { // Quick Fix for CNAME
			answers = make([]DNSRecord, 1)
			answers[0] = a
		}
	}
	authorities := make([]DNSRecord, header.Num_authorities)
	for i := 0; i < int(header.Num_authorities); i++ {
		authorities[i] = ParseRecord(buf)
	}

	additionals := make([]DNSRecord, header.Num_additionals)
	for i := 0; i < int(header.Num_additionals); i++ {
		additionals[i] = ParseRecord(buf)
	}

	return DNSPacket{Header: header, Question: questions, Answer: answers, Authorities: authorities, Additionals: additionals}
}

func ParseIP(ip []byte) string {
	if len(ip) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else {
		return fmt.Sprintf("%s", ip)
	}
}
