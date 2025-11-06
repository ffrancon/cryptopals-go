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

func encryptWithSecretString(bytes, secret, key []byte) []byte {
	combined := append(bytes, secret...)
	return pkg.AESECBEncrypt(combined, key)

}

func findBlockCipherKeySize(bytes, key []byte) int {
	if len(bytes) < len(key)*2 {
		fmt.Fprintf(os.Stderr, "Input bytes length must be at least twice the key length\n")
		os.Exit(1)
	}
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
	// Use a sample of 32 bytes to find the key size
	sample := bytes.Repeat([]byte("A"), 32)
	keysize := findBlockCipherKeySize(sample, key)

	// Check if the encryption mode is ECB
	isECBMode := pkg.ScoringECBMode(pkg.AESECBEncrypt(sample, key), keysize) > 0
	if !isECBMode {
		fmt.Println("The encryption mode is CBC")
		return
	}

	// Convert the base64 secret string to bytes
	secret, err := pkg.Base64ToBytes(b64SecretString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting base64 string to bytes: %v\n", err)
		os.Exit(1)
	}

	result := make([]byte, len(secret))
	chunks := pkg.ChunkBytes(secret, keysize)

	// For each chunk of the secret string
	for _, c := range chunks {
		chunk := make([]byte, len(c))
		// We will iterate over the keysize in a single block to break the secret string byte by byte
		for k := range keysize {
			// If k is greater than the length of the current chunk, we are done
			if k > len(c)-1 {
				break
			}
			// This block is i byte(s) short of the keysize
			block := make([]byte, keysize-1-k)
			encryptedBlock := encryptWithSecretString(block, c, key)[:keysize]
			// We will test all the possible values for the last byte of the block until we find the one that matches the encrypted block
			for j := range 256 {
				// Reconstruct the full block
				reconstructed := append(block, chunk[:k]...)
				reconstructed = append(reconstructed, byte(j))
				encryptedReconstructed := pkg.AESECBEncrypt(reconstructed, key)
				if bytes.Equal(encryptedBlock, encryptedReconstructed[:keysize]) {
					chunk[k] = byte(j)
					break
				}
			}
		}
		result = append(result, chunk...)
	}

	fmt.Printf("Decrypted secret string is:\n%s", result)
}
