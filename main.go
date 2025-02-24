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

func findBlockCipherKeySize(bytes []byte) int {
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
	// Find keysize and encryption mode
	ECBTestString := []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	keysize := findBlockCipherKeySize(ECBTestString)
	fmt.Printf("The key size is: %d\n", keysize)
	isECBMode := pkg.ScoringECBMode(pkg.AESECBEncrypt(ECBTestString, key), keysize) > 0
	if !isECBMode {
		fmt.Println("The encryption mode is CBC")
		return
	}

	breakedMessageBlock := make([]byte, keysize)
	// We will iterate over the keysize in a single block to break the secret string byte by byte
	for i := 0; i < keysize; i++ {
		// This block is i byte(s) short of the keysize
		defaultBlock := make([]byte, keysize-1-i)
		encryptedCrackBlock := encryptWithSecretString(defaultBlock, key)[:keysize]
		// We will test all the possible values for the last byte of the block until we find the one that matches the encrypted block
		for j := 0; j < 256; j++ {
			extendedCrackBlock := append(defaultBlock, breakedMessageBlock[:i]...)
			extendedCrackBlock = append(extendedCrackBlock, byte(j))
			encodedExtendedCrackBlock := pkg.AESECBEncrypt(extendedCrackBlock, key)
			if bytes.Equal(encryptedCrackBlock, encodedExtendedCrackBlock[:keysize]) {
				breakedMessageBlock[i] = byte(j)
				break
			}
		}
	}

	fmt.Printf("First block of the secret string is: %s\n", breakedMessageBlock)
}
