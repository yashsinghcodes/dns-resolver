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
	name   []byte
	type_  uint16
	class_ uint16
}

func Header_to_bytes(header *DNSHeader) []byte {
	idBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(idBytes, uint16(header.Id))

	flagBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagBytes, uint16(header.Flag))

	num_questionsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(num_questionsBytes, uint16(header.Num_questions))

	num_answersBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(num_answersBytes, uint16(header.Num_answers))

	num_autBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(num_autBytes, uint16(header.Num_authorities))

	num_addBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(num_addBytes, uint16(header.Num_additionals))

	return append(append(append(append(idBytes, flagBytes...), append(num_questionsBytes, num_answersBytes...)...), num_autBytes...), num_addBytes...)
}

func QuestionToBytes(question *DNSQuestion) []byte {
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, uint16(question.type_))

	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, uint16(question.class_))

	return append(question.name, append(typeBytes, classBytes...)...)
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

func Build_query(domain string, record_type uint16, type_a uint16, class_in uint16) []byte {
	name := EncodeDNSName(domain)
	rand.Seed(1)
	id := rand.Intn(65535)
	recursion := 1 << 8
	header := DNSHeader{Id: uint16(id), Flag: uint16(recursion), Num_questions: 1, Num_answers: 0, Num_additionals: 0, Num_authorities: 0}
	question := DNSQuestion{name: name, type_: record_type, class_: class_in}
	return append(Header_to_bytes(&header), QuestionToBytes(&question)...)
}

// TEST FUNCTION

// func main() {

// 	// test query...

// 	query := Build_query("www.example.com", 1, 1, 1)
// 	addr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
// 	if err != nil {
// 		fmt.Fprintf(os.Stdout, "Error in connecting")
// 		return
// 	}
// 	conn, err := net.DialUDP("udp", nil, addr)
// 	if err != nil {
// 		fmt.Fprintf(os.Stdout, "Error in connecting")
// 		return
// 	}
// 	_, err = conn.Write(query)
// 	if err != nil {
// 		fmt.Fprintf(os.Stdout, "Error in connecting")
// 		return
// 	}
// 	res := make([]byte, 1024)
// 	n, _, err := conn.ReadFromUDP(res)
// 	if err != nil {
// 		fmt.Fprintf(os.Stdout, "Error in connecting")
// 		return
// 	}
// 	fmt.Println(res[:n])
// }
