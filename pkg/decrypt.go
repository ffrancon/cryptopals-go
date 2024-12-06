package pkg

import (
	"bufio"
	"fmt"
	"os"
)

type Message struct {
	Key       byte
	Decrypted []byte
	score     float64
}

func DecryptXorSingleByte(str string) (m Message) {
	bytes, err := HexStrToBytes(str)
	if err != nil {
		fmt.Println(err)
		return Message{}
	}
	m.score = 999
	for i := range 256 {
		byte := byte(i)
		xor := XorSingleByte(bytes, byte)
		score := ScoringEnglish(xor)
		if score < m.score {
			m = Message{byte, xor, score}
		}
	}
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

	m.score = 999
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mm := DecryptXorSingleByte(scanner.Text())
		if mm.score < m.score {
			m = mm
		}
	}
	check(scanner.Err())

	return m
}
