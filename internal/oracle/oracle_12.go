package oracle

import (
	"bytes"
	"ffrancon/cryptopals-go/internal/aes"
	"ffrancon/cryptopals-go/internal/encoding"
	"ffrancon/cryptopals-go/internal/scoring"
	"ffrancon/cryptopals-go/internal/utils"
	"fmt"
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

func (o *SecretOracle) encryptWithSecretString(bytes, secret []byte) ([]byte, error) {
	combined := append(bytes, secret...)
	encrypted, err := aes.AESECBEncrypt(combined, o.key)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (o *SecretOracle) findAESKeySize() (int, error) {
	prevLen := 0
	for i := range 32 {
		output, err := aes.AESECBEncrypt(bytes.Repeat([]byte("A"), i+1), o.key)
		if err != nil {
			return 0, err
		}
		// If the output length is different from the previous output length, we found the key size
		if len(output) != prevLen && prevLen != 0 {
			return i, nil
		}
		prevLen = len(output)
	}
	return 0, fmt.Errorf("could not determine key size")
}

func (o *SecretOracle) breakSecretString(secret []byte, keysize int) (decrypted []byte, err error) {
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
			encryptedBlock, err := o.encryptWithSecretString(block, c)
			if err != nil {
				return nil, err
			}
			// We will test all the possible values for the last byte of the block until we find the one that matches the encrypted block
			for b := range 256 {
				// Reconstruct the full block
				reconstructed := append(block, chunk[:k]...)
				reconstructed = append(reconstructed, byte(b))
				encryptedReconstructed, err := aes.AESECBEncrypt(reconstructed, o.key)
				if err != nil {
					return nil, err
				}
				if bytes.Equal(encryptedBlock, encryptedReconstructed[:keysize]) {
					chunk[k] = byte(b)
					break
				}
			}
		}
		decrypted = append(decrypted, chunk...)
	}
	return decrypted, nil
}

func AESECBOracle() ([]byte, error) {
	oracle := NewSecretOracle()

	keysize, err := oracle.findAESKeySize()
	if err != nil {
		return nil, fmt.Errorf("could not determine key size: %w", err)
	}

	// Validate that the encryption mode is ECB (useless but required by the exercise)
	encrypted, err := aes.AESECBEncrypt(bytes.Repeat([]byte("A"), keysize*2), oracle.key)
	if err != nil {
		return nil, fmt.Errorf("error during encryption: %w", err)
	}
	isECBMode := scoring.ScoringECBMode(encrypted, keysize) > 0
	if !isECBMode {
		return nil, fmt.Errorf("encryption mode is not ECB")
	}

	secret, err := encoding.Base64ToBytes(b64SecretString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret string: %w", err)
	}
	plaintext, err := oracle.breakSecretString(secret, keysize)
	if err != nil {
		return nil, fmt.Errorf("could not break secret string: %w", err)
	}

	return plaintext, nil
}
