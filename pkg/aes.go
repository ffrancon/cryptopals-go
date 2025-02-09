package pkg

import (
	"crypto/aes"
)

func getBlockEncryptParams(key []byte, plaintext []byte) (int, []byte, [][]byte) {
	keySize := len(key)
	paddedPlainText := AddPKCS7Padding(plaintext, keySize)
	chunks := ChunkBytes(paddedPlainText, keySize)
	encrypted := make([]byte, len(paddedPlainText))
	return keySize, encrypted, chunks
}

func AesECBEncrypt(plaintext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	Check(err)
	keySize, encrypted, chunks := getBlockEncryptParams(key, plaintext)
	for i, c := range chunks {
		cipher.Encrypt(encrypted[i*keySize:], c)
	}
	return encrypted
}

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
	keySize, encrypted, chunks := getBlockEncryptParams(key, plaintext)
	for i, c := range chunks {
		if i == 0 {
			cipher.Encrypt(encrypted[:keySize], XorBytes(c, iv))
		} else {
			cipher.Encrypt(encrypted[i*keySize:], XorBytes(c, encrypted[(i-1)*keySize:i*keySize]))
		}
	}

	return encrypted
}

func AESCBCDecrypt(ciphertext, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	Check(err)
	keySize := len(key)
	chunks := ChunkBytes(ciphertext, keySize)
	decrypted := make([]byte, len(ciphertext))
	dc := make([]byte, keySize)

	for i, c := range chunks {
		cipher.Decrypt(dc, c)
		if i == 0 {
			copy(decrypted[:keySize], XorBytes(dc, iv))
		} else {
			copy(decrypted[i*keySize:], XorBytes(dc, chunks[i-1]))
		}
	}

	return decrypted
}
