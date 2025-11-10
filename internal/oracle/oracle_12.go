package oracle

import (
	"bytes"
	"ffrancon/cryptopals-go/internal/aes"
	"ffrancon/cryptopals-go/internal/encoding"
	"ffrancon/cryptopals-go/internal/scoring"
	"ffrancon/cryptopals-go/internal/utils"
	"fmt"
	"os"
)

var b64SecretString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

type SecretOracle struct {
	key []byte
}

func NewSecretOracle() *SecretOracle {
	return &SecretOracle{
		key: utils.GenerateRandomBytes(16),
	}
}

func (o *SecretOracle) encryptWithSecretString(bytes, secret []byte) []byte {
	combined := append(bytes, secret...)
	return aes.AESECBEncrypt(combined, o.key)
}

func (o *SecretOracle) findAESKeySize() int {
	prevLen := 0
	for i := range 32 {
		output := aes.AESECBEncrypt(bytes.Repeat([]byte("A"), i+1), o.key)
		// If the output length is different from the previous output length, we found the key size
		if len(output) != prevLen && prevLen != 0 {
			return i
		}
		prevLen = len(output)
	}
	return 0
}

func AESECBOracle() (decrypted []byte) {
	oracle := NewSecretOracle()

	keysize := oracle.findAESKeySize()
	if keysize == 0 {
		fmt.Println("Could not determine key size")
		return
	}

	// Check if the encryption mode is ECB
	isECBMode := scoring.ScoringECBMode(aes.AESECBEncrypt(bytes.Repeat([]byte("A"), keysize*2), oracle.key), keysize) > 0
	if !isECBMode {
		fmt.Println("The encryption mode is CBC")
		return
	}

	// Convert the base64 secret string to bytes
	secret, err := encoding.Base64ToBytes(b64SecretString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting base64 string to bytes: %v\n", err)
		os.Exit(1)
	}

	chunks := utils.ChunkBytes(secret, keysize)

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
			encryptedBlock := oracle.encryptWithSecretString(block, c)[:keysize]
			// We will test all the possible values for the last byte of the block until we find the one that matches the encrypted block
			for j := range 256 {
				// Reconstruct the full block
				reconstructed := append(block, chunk[:k]...)
				reconstructed = append(reconstructed, byte(j))
				encryptedReconstructed := aes.AESECBEncrypt(reconstructed, oracle.key)
				if bytes.Equal(encryptedBlock, encryptedReconstructed[:keysize]) {
					chunk[k] = byte(j)
					break
				}
			}
		}
		decrypted = append(decrypted, chunk...)
	}
	return decrypted
}
