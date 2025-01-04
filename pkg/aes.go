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

func AESCBCEncrypt(plaintext, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	Check(err)
	keySize := len(key)
	paddedTxt := AddPKCS7Padding(plaintext, keySize)
	chunks := ChunkBytes(paddedTxt, keySize)
	encrypted := make([]byte, len(paddedTxt))

	for i, c := range chunks {
		if i == 0 {
			cipher.Encrypt(encrypted[:keySize], XorBytes(c, iv))
		} else {
			cipher.Encrypt(encrypted[i*keySize:], XorBytes(c, encrypted[(i-1)*keySize:i*keySize]))
		}
	}

	return encrypted
}
