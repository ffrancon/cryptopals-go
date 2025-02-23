package pkg

import (
	"bufio"
	"os"
)

type ScoredMessage struct {
	Key       byte
	Decrypted []byte
	Score     float64
}

func DecryptXorSingleByte(bytes []byte, index int) (message ScoredMessage) {
	message.Score = -1
	for i := range 256 {
		byte := byte(i)
		xor := XorSingleByte(bytes, byte)
		score := ScoringEnglish(xor)
		if IsBetterEnglishScore(score, message.Score) {
			message = ScoredMessage{byte, xor, score}
		}
	}
	return message
}

func DecryptXorSingleByteFromBatchFile(path string) (message ScoredMessage) {
	file, err := os.Open(path)
	Check(err)
	defer file.Close()

	message.Score = -1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		bytes := HexStrToBytes(str)
		decryptedStr := DecryptXorSingleByte(bytes, 999)
		if IsBetterEnglishScore(decryptedStr.Score, message.Score) {
			message = decryptedStr
		}
	}
	Check(scanner.Err())

	return message
}
