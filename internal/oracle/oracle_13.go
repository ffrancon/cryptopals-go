package oracle

import (
	"bytes"
	"errors"
	"ffrancon/cryptopals-go/internal/aes"
	"ffrancon/cryptopals-go/internal/utils"
	"fmt"
	"regexp"
	"strings"
)

func QueryStringToMap(query string) map[string]string {
	result := make(map[string]string)
	for _, kv := range strings.Split(query, "&") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

// Simple email validation regex but exludes & and = for safety
var emailRe = regexp.MustCompile(`^[^@\s&=]+@[^@\s&=]+\.[^@\s&=]+$`)

type ProfileOracle struct {
	key []byte
}

func NewProfileOracle() *ProfileOracle {
	return &ProfileOracle{
		key: utils.GenerateRandomBytes(16),
	}
}

func (o *ProfileOracle) generateUserProfile(email string) (string, error) {
	if !emailRe.MatchString(email) {
		return "", errors.New("invalid email format")
	}
	return "email=" + email + "&uid=10&role=user", nil
}

func (o *ProfileOracle) Encrypt(email string) ([]byte, error) {
	profile, err := o.generateUserProfile(email)
	if err != nil {
		return nil, err
	}
	encrypted, err := aes.AESECBEncrypt([]byte(profile), o.key)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (o *ProfileOracle) Decrypt(ciphertext []byte) ([]byte, error) {
	decrypted, err := aes.AESECBDecrypt(ciphertext, o.key)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func AESECBCutAndPasteAttack(email string) (string, error) {
	// Email must be chosen precisely so that "admin" is at the start of a block after padding
	if len(email) != 13 {
		return "", fmt.Errorf("email must be 13 characters long for this attack")
	}

	oracle := NewProfileOracle()

	ciphertext, err := oracle.Encrypt(email)
	if err != nil {
		return "", fmt.Errorf("encryption error: %v", err)
	}

	// Right sized random email + admin + 11 bytes of padding for valid PKCS#7
	corrupted, err := oracle.Encrypt("aaaaaa@b.cadmin" + string(bytes.Repeat([]byte{11}, 11)))
	if err != nil {
		return "", fmt.Errorf("encryption error: %v", err)
	}
	// Rebuild ciphertext to have "role=admin" block positioned correctly
	chunkedCiphertext := utils.ChunkBytes(ciphertext, 16)
	chunkedCorrupted := utils.ChunkBytes(corrupted, 16)
	chunkedCiphertext[2] = chunkedCorrupted[1]

	// Decrypt modified ciphertext
	reconstructed := utils.FlattenBytesChunks(chunkedCiphertext)
	profile, err := oracle.Decrypt(reconstructed)
	if err != nil {
		return "", fmt.Errorf("decryption error: %v", err)
	}

	return string(profile), nil
}
