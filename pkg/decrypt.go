package pkg

import (
	"bufio"
	"os"
)

type Message struct {
	Key       byte
	Decrypted []byte
	Score     float64
}

func DecryptXorSingleByte(bytes []byte, index int) (m Message) {
	m.Score = -1
	for i := range 256 {
		byte := byte(i)
		xor := XorSingleByte(bytes, byte)
		score := ScoringEnglish(xor)
		if IsBetterEnglishScore(score, m.Score) {
			m = Message{byte, xor, score}
		}
	}
	return m
}

func DecryptXorSingleByteFromBatchFile(path string) (m Message) {
	file, err := os.Open(path)
	Check(err)
	defer file.Close()

	m.Score = -1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		bytes := HexStrToBytes(str)
		mm := DecryptXorSingleByte(bytes, 999)
		if IsBetterEnglishScore(mm.Score, m.Score) {
			m = mm
		}
	}
	Check(scanner.Err())

	return m
}
