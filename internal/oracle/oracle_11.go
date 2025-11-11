package oracle

import (
	"ffrancon/cryptopals-go/internal/aes"
	"ffrancon/cryptopals-go/internal/scoring"
	"ffrancon/cryptopals-go/internal/utils"
	"fmt"
	"math/rand"
)

func AESECBOrCBCOracle(str string) (string, error) {
	fill := utils.GenerateRandomBytes(rand.Intn(6) + 5)
	bytes := make([]byte, len(fill)*2+len([]byte(str)))
	bytes = append(bytes, fill...)
	bytes = append(bytes, []byte(str)...)
	bytes = append(bytes, fill...)

	key := utils.GenerateRandomBytes(16)
	toScore := make([]byte, 0)

	switch mode := rand.Intn(2); mode {
	case 0:
		fmt.Println("Encrypting with ECB")
		encrypted, err := aes.AESECBEncrypt(bytes, key)
		if err != nil {
			return "", fmt.Errorf("encryption error: %w", err)
		}
		toScore = append(toScore, encrypted...)
	case 1:
		fmt.Println("Encrypting with CBC")
		iv := utils.GenerateRandomBytes(16)
		encrypted, err := aes.AESCBCEncrypt(bytes, key, iv)
		if err != nil {
			return "", fmt.Errorf("encryption error: %w", err)
		}
		toScore = append(toScore, encrypted...)
	}

	if scoring.ScoringECBMode(toScore, 16) > 0 {
		return "ECB", nil
	}
	return "CBC", nil
}
