package pkg

import (
	"crypto/aes"
)

func AesECBDecrypt(ciphertext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	Check(err)
	chunks := ChunkBytes(ciphertext, 16)
	decrypted := make([]byte, len(ciphertext))
	for i, c := range chunks {
		cipher.Decrypt(decrypted[i*16:], c)
	}
	return decrypted
}
