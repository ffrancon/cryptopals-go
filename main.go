package main

import (
	"ffrancon/cryptopals-go/pkg"
	"fmt"
	"math/rand"
)

func oracle(str string) {
	fill := pkg.GenerateRandomBytes(rand.Intn(6) + 5)
	bytes := make([]byte, len(fill)*2+len([]byte(str)))

	bytes = append(bytes, fill...)
	bytes = append(bytes, []byte(str)...)
	bytes = append(bytes, fill...)

	mode := rand.Intn(1)
	key := pkg.GenerateRandomBytes(16)

	if mode == 0 {
		fmt.Println("Encrypting with ECB")
		// TODO encrypt with ECB
	} else {
		fmt.Println("Encrypting with CBC")
		iv := pkg.GenerateRandomBytes(16)
		pkg.AESCBCEncrypt(bytes, key, iv)
	}
}

func main() {
	fmt.Println("Hello, Cryptopals!")
}
