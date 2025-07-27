package main

import (
	"bytes"
	"ffrancon/cryptopals-go/pkg"
	"fmt"
	"os"
)

// [49 246 193 241 155 103 45 91 5 172 204 196 147 234 106 133]
var key = []byte{49, 246, 193, 241, 155, 103, 45, 91, 5, 172, 204, 196, 147, 234, 106, 133}
var b64SecretString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func encryptWithSecretString(bytes, key []byte) []byte {
	decodedSecretStr, err := pkg.Base64ToBytes(b64SecretString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting base64 string to bytes: %v\n", err)
		os.Exit(1)
	}
	combined := append(bytes, decodedSecretStr...)
	return pkg.AESECBEncrypt(combined, key)

}

func findBlockCipherKeySize(bytes []byte) int {
	prevLen := 0
	slice := make([]byte, 0)
	for i := range bytes {
		slice = append(slice, bytes[i])
		output := pkg.AESECBEncrypt(slice, key)
		// If the output length is different from the previous output length, we found the key size
		if len(output) != prevLen && prevLen != 0 {
			return i
		}
		prevLen = len(output)
	}
	return 0
}

func main() {
	// Find keysize and encryption mode
	ECBTestString := []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	keysize := findBlockCipherKeySize(ECBTestString)

	// Check if the encryption mode is ECB
	isECBMode := pkg.ScoringECBMode(pkg.AESECBEncrypt(ECBTestString, key), keysize) > 0
	if !isECBMode {
		fmt.Println("The encryption mode is CBC")
		return
	}

	brokenMessage := make([]byte, keysize)
	// We will iterate over the keysize in a single block to break the secret string byte by byte
	for k := range keysize {
		// This block is i byte(s) short of the keysize
		block := make([]byte, keysize-1-k)
		encryptedBlock := encryptWithSecretString(block, key)[:keysize]
		// We will test all the possible values for the last byte of the block until we find the one that matches the encrypted block
		for j := range 256 {
			fullBlock := append(block, brokenMessage[:k]...)
			fullBlock = append(fullBlock, byte(j))
			encryptedFullBlock := pkg.AESECBEncrypt(fullBlock, key)
			if bytes.Equal(encryptedBlock, encryptedFullBlock[:keysize]) {
				brokenMessage[k] = byte(j)
				break
			}
		}
	}

	fmt.Printf("First block of the secret string is: %s\n", brokenMessage)
}
