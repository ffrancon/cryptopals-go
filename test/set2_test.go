package tests

import (
	"ffrancon/cryptopals-go/encoding"
	"ffrancon/cryptopals-go/pkg"
	"ffrancon/cryptopals-go/utils"
	"regexp"
	"testing"
)

func TestChallenge9(t *testing.T) {
	res := utils.AddPKCS7Padding([]byte("YELLOW SUBMARINE"), 20)
	exp := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(res) != exp {
		t.Errorf("expected %s, got %s", exp, res)
	}
}

func TestChallenge10(t *testing.T) {
	data := utils.ReadFile("../data/10.txt")
	bytes, err := encoding.Base64ToBytes(data)
	if err != nil {
		t.Errorf("error converting base64 to bytes: %v", err)
	}
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	decrypted := pkg.AESCBCDecrypt(bytes, key, iv)
	reg := regexp.MustCompile(`You thought that I was weak, Boy, you're dead wrong`)
	if !reg.Match(decrypted) {
		t.Errorf("expected %s, got %s", reg, decrypted)
	}
}
