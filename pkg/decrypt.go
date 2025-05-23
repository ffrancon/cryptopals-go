package pkg

import (
	"bufio"
	"ffrancon/cryptopals/encoding"
	"ffrancon/cryptopals/utils"
	"fmt"
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
	utils.Check(err)
	defer file.Close()

	message.Score = -1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		bytes, err := encoding.HexStrToBytes(str)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error converting hex string to bytes:", err)
			os.Exit(1)
		}
		decryptedStr := DecryptXorSingleByte(bytes, 999)
		if IsBetterEnglishScore(decryptedStr.Score, message.Score) {
			message = decryptedStr
		}
	}
	utils.Check(scanner.Err())

	return message
}
