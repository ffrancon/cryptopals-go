package pkg

import (
	"ffrancon/cryptopals-go/utils"
	"fmt"
	"math/rand"
)

func AESECBOrCBCOracle(str string) string {
	fill := utils.GenerateRandomBytes(rand.Intn(6) + 5)
	bytes := make([]byte, len(fill)*2+len([]byte(str)))
	bytes = append(bytes, fill...)
	bytes = append(bytes, []byte(str)...)
	bytes = append(bytes, fill...)

	key := utils.GenerateRandomBytes(16)
	encrypted := make([]byte, 0)

	mode := rand.Intn(2)
	if mode == 0 {
		fmt.Println("Encrypting with ECB")
		encrypted = append(encrypted, AESECBEncrypt(bytes, key)...)
	} else {
		fmt.Println("Encrypting with CBC")
		iv := utils.GenerateRandomBytes(16)
		encrypted = append(encrypted, AESCBCEncrypt(bytes, key, iv)...)
	}

	if ScoringECBMode(encrypted, 16) > 0 {
		return "ECB"
	}
	return "CBC"
}
