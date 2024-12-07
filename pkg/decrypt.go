package pkg

import (
	"bufio"
	"fmt"
	"os"
)

type Message struct {
	Key       byte
	Decrypted []byte
	Score     float64
}

func DecryptXorSingleByte(str string) (m Message) {
	bytes, err := HexStrToBytes(str)
	if err != nil {
		fmt.Println(err)
		return Message{}
	}
	m.Score = 9999
	for i := range 256 {
		byte := byte(i)
		xor := XorSingleByte(bytes, byte)
		score := EvaluateEnglish(xor)
		if score < m.Score {
			m = Message{byte, xor, score}
		}
	}
	fmt.Printf("Key: %d, Decrypted: %s, Score: %f\n", m.Key, string(m.Decrypted), m.Score)
	return m
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func DecryptXorSingleByteFromBatchFile(path string) (m Message) {
	file, err := os.Open(path)
	check(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mm := DecryptXorSingleByte(BytesToHexStr(scanner.Bytes()))
		if mm.Score > m.Score {
			m = mm
		}
	}
	check(scanner.Err())

	return m
}
