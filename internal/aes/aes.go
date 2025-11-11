package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"ffrancon/cryptopals-go/internal/utils"
	"ffrancon/cryptopals-go/internal/xor"
)

func getEncryptParams(key []byte, rawData []byte) (int, []byte, [][]byte) {
	keySize := len(key)
	pkcs7Padded := utils.AddPKCS7Padding(rawData, keySize)
	blocks := utils.ChunkBytes(pkcs7Padded, keySize)
	output := make([]byte, len(pkcs7Padded))
	return keySize, output, blocks
}

func AESCipher(key []byte) (cipher cipher.Block, err error) {
	cipher, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

func AESECBEncrypt(rawData, key []byte) ([]byte, error) {
	cipher, err := AESCipher(key)
	if err != nil {
		return nil, err
	}
	keySize, output, blocks := getEncryptParams(key, rawData)
	for i, c := range blocks {
		cipher.Encrypt(output[i*keySize:], c)
	}
	return output, nil
}

func AESECBDecrypt(encryptedData, key []byte) ([]byte, error) {
	ks := len(key)
	cipher, err := AESCipher(key)
	if err != nil {
		return nil, err
	}
	blocks := utils.ChunkBytes(encryptedData, ks)
	output := make([]byte, len(encryptedData))
	for i, c := range blocks {
		cipher.Decrypt(output[i*ks:], c)
	}
	return output, nil
}

func AESCBCEncrypt(rawData, key, iv []byte) ([]byte, error) {
	cipher, err := AESCipher(key)
	if err != nil {
		return nil, err
	}
	keySize, output, blocks := getEncryptParams(key, rawData)
	for i, block := range blocks {
		switch i {
		case 0:
			cipher.Encrypt(output[:keySize], xor.XorBytes(block, iv))
		default:
			cipher.Encrypt(output[i*keySize:], xor.XorBytes(block, output[(i-1)*keySize:i*keySize]))
		}
	}
	return output, nil
}

func AESCBCDecrypt(encryptedData, key, iv []byte) ([]byte, error) {
	cipher, err := AESCipher(key)
	if err != nil {
		return nil, err
	}
	keySize := len(key)
	blocks := utils.ChunkBytes(encryptedData, keySize)
	output := make([]byte, len(encryptedData))
	decryptedBlock := make([]byte, keySize)
	for i, c := range blocks {
		cipher.Decrypt(decryptedBlock, c)
		switch i {
		case 0:
			copy(output[:keySize], xor.XorBytes(decryptedBlock, iv))
		default:
			copy(output[i*keySize:], xor.XorBytes(decryptedBlock, blocks[i-1]))
		}
	}
	return output, nil
}
