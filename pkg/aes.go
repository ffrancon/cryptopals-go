package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"ffrancon/cryptopals/utils"
	"fmt"
	"os"
)

func getEncryptParams(key []byte, rawData []byte) (int, []byte, [][]byte) {
	keySize := len(key)
	pkcs7Padded := utils.AddPKCS7Padding(rawData, keySize)
	blocks := utils.ChunkBytes(pkcs7Padded, keySize)
	output := make([]byte, len(pkcs7Padded))
	return keySize, output, blocks
}

func getAESCipher(key []byte) (cipher cipher.Block) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating AES cipher: %v\n", err)
		os.Exit(1)
	}
	return cipher
}

func AESECBEncrypt(rawData, key []byte) []byte {
	cipher := getAESCipher(key)
	keySize, output, blocks := getEncryptParams(key, rawData)
	for i, c := range blocks {
		cipher.Encrypt(output[i*keySize:], c)
	}
	return output
}

func AESECBDecrypt(encryptedData, key []byte) []byte {
	cipher := getAESCipher(key)
	blocks := utils.ChunkBytes(encryptedData, 16)
	output := make([]byte, len(encryptedData))
	for i, c := range blocks {
		cipher.Decrypt(output[i*16:], c)
	}
	return output
}

func AESCBCEncrypt(rawData, key, iv []byte) []byte {
	cipher := getAESCipher(key)
	keySize, output, blocks := getEncryptParams(key, rawData)
	for i, block := range blocks {
		if i == 0 {
			cipher.Encrypt(output[:keySize], XorBytes(block, iv))
		} else {
			cipher.Encrypt(output[i*keySize:], XorBytes(block, output[(i-1)*keySize:i*keySize]))
		}
	}
	return output
}

func AESCBCDecrypt(encryptedData, key, iv []byte) []byte {
	cipher := getAESCipher(key)
	keySize := len(key)
	blocks := utils.ChunkBytes(encryptedData, keySize)
	output := make([]byte, len(encryptedData))
	decryptedBlock := make([]byte, keySize)
	for i, c := range blocks {
		cipher.Decrypt(decryptedBlock, c)
		if i == 0 {
			copy(output[:keySize], XorBytes(decryptedBlock, iv))
		} else {
			copy(output[i*keySize:], XorBytes(decryptedBlock, blocks[i-1]))
		}
	}
	return output
}
