package query

import (
	"encoding/binary"
	"math/rand"
	"strings"
)

type DNSHeader struct {
	Id              uint16
	Flag            uint16
	Num_questions   uint16
	Num_answers     uint16
	Num_authorities uint16
	Num_additionals uint16
}

type DNSQuestion struct {
	Name   []byte
	Type_  uint16
	Class_ uint16
}

func Header_to_bytes(header *DNSHeader) []byte {
	var data []byte
	data = append(data,
		byte(header.Id)>>8, byte(header.Id),
		byte(header.Flag)>>8, byte(header.Flag),
		byte(header.Num_questions)>>8, byte(header.Num_questions),
		byte(header.Num_answers)>>8, byte(header.Num_answers),
		byte(header.Num_authorities)>>8, byte(header.Num_authorities),
		byte(header.Num_additionals)>>8, byte(header.Num_additionals),
	)
	return data
}

func QuestionToBytes(question *DNSQuestion) []byte {
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, uint16(question.Type_))

	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, uint16(question.Class_))

	return append(question.Name, append(typeBytes, classBytes...)...)
}

func EncodeDNSName(domain string) []byte {
	var encode []byte
	for _, value := range strings.Split(domain, ".") {
		encode = append(encode, byte(len(value)))
		encode = append(encode, []byte(value)...)
	}
	encode = append(encode, 0x00)
	return encode
}

func Build_query(domain string, record_type uint16, class_in uint16) []byte {
	name := EncodeDNSName(domain)
	rand.Seed(1)
	id := rand.Intn(65535)
	// recursion := 1 << 8
	header := DNSHeader{Id: uint16(id), Flag: 0, Num_questions: 1, Num_answers: 0, Num_additionals: 0, Num_authorities: 0}
	question := DNSQuestion{Name: name, Type_: record_type, Class_: class_in}
	return append(Header_to_bytes(&header), QuestionToBytes(&question)...)
}
