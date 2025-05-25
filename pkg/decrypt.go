package pkg

import (
	"bufio"
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
			message = ScoredMessage{
				Key:       byte,
				Decrypted: xor,
				Score:     score,
			}
		}
	}
	return message
}

func DecryptXorSingleByteFromBatchFile(path string) (message ScoredMessage) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening file:", err)
		os.Exit(1)
	}
	defer file.Close()
	message.Score = -1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		bytes, err := HexStrToBytes(str)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error converting hex string to bytes:", err)
			os.Exit(1)
		}
		decryptedStr := DecryptXorSingleByte(bytes, 999)
		if IsBetterEnglishScore(decryptedStr.Score, message.Score) {
			message = decryptedStr
		}
	}
	err = scanner.Err()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading file:", err)
		os.Exit(1)
	}

	return message
}
