package pkg

import (
	"crypto/aes"
	"fmt"
)

func getEncryptParams(key []byte, plaintext []byte) (int, []byte, [][]byte) {
	keySize := len(key)
	paddedPlainText := AddPKCS7Padding(plaintext, keySize)
	blocks := ChunkBytes(paddedPlainText, keySize)
	encrypted := make([]byte, len(paddedPlainText))
	return keySize, encrypted, blocks
}

func AESECBEncrypt(plaintext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	Check(err)
	keySize, encrypted, blocks := getEncryptParams(key, plaintext)
	for i, c := range blocks {
		cipher.Encrypt(encrypted[i*keySize:], c)
	}
	fmt.Printf("Encrypted: %v\n", encrypted)
	return encrypted
}

func AESECBDecrypt(ciphertext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	Check(err)
	blocks := ChunkBytes(ciphertext, 16)
	decrypted := make([]byte, len(ciphertext))
	for i, c := range blocks {
		cipher.Decrypt(decrypted[i*16:], c)
	}
	return decrypted
}

func AESCBCEncrypt(plaintext, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	Check(err)
	keySize, encrypted, blocks := getEncryptParams(key, plaintext)
	for i, c := range blocks {
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
	blocks := ChunkBytes(ciphertext, keySize)
	decrypted := make([]byte, len(ciphertext))
	dc := make([]byte, keySize)

	for i, c := range blocks {
		cipher.Decrypt(dc, c)
		if i == 0 {
			copy(decrypted[:keySize], XorBytes(dc, iv))
		} else {
			copy(decrypted[i*keySize:], XorBytes(dc, blocks[i-1]))
		}
	}

	return decrypted
}
