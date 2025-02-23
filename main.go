package main

import (
	"bytes"
	"ffrancon/cryptopals-go/pkg"
	"fmt"
)

// [49 246 193 241 155 103 45 91 5 172 204 196 147 234 106 133]
var key = []byte{49, 246, 193, 241, 155, 103, 45, 91, 5, 172, 204, 196, 147, 234, 106, 133}
var b64SecretString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func encryptWithSecretString(bytes, key []byte) []byte {
	decodedSecretString := pkg.Base64ToBytes(b64SecretString)
	combinedBytes := append(bytes, decodedSecretString...)
	return pkg.AESECBEncrypt(combinedBytes, key)

}

func findBlockKeySize(bytes []byte) int {
	previousOutputLength := 0
	toIterateIn := make([]byte, 0)
	for i := 0; i < len(bytes); i++ {
		toIterateIn = append(toIterateIn, bytes[i])
		output := pkg.AESECBEncrypt(toIterateIn, key)
		// If the output length is different from the previous output length, we found the key size
		if len(output) != previousOutputLength && previousOutputLength != 0 {
			return i
		}
		previousOutputLength = len(output)
	}
	return 0
}

func main() {
	plaintext := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	byteData := []byte(plaintext)
	keysize := findBlockKeySize(byteData)
	fmt.Printf("The key size is: %d\n", keysize)
	isECBMode := pkg.ScoringECBMode(pkg.AESECBEncrypt(byteData, key), keysize) > 0
	if isECBMode {
		fmt.Println("The encryption mode is ECB")
	} else {
		fmt.Println("The encryption mode is CBC")
	}

	// This block is one byte short of the keysize
	crackBlock := make([]byte, keysize-1)
	for i := 0; i < keysize-1; i++ {
		crackBlock[i] = 97
	}

	// The last byte of the block will be the first byte of the secret string
	encryptedCrackBlock := encryptWithSecretString(crackBlock, key)[:keysize]
	// We will create a dictionary with all the possible values for the last byte of the block
	dictionary := make(map[byte][]byte)
	for i := 0; i < 256; i++ {
		extendedCrackBlock := append(crackBlock, byte(i))
		dictionary[byte(i)] = pkg.AESECBEncrypt(extendedCrackBlock, key)
	}
	firstByte := byte(0)
	for d := range dictionary {
		if bytes.Equal(dictionary[d], encryptedCrackBlock) {
			firstByte = d
			break
		}
	}
	fmt.Printf("First letter of the secret string is: %s\n", string(firstByte))
}
