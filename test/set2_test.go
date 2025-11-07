package tests

import (
	"ffrancon/cryptopals-go/pkg"
	"regexp"
	"testing"
)

func TestChallenge9(t *testing.T) {
	res := pkg.AddPKCS7Padding([]byte("YELLOW SUBMARINE"), 20)
	exp := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(res) != exp {
		t.Errorf("expected %s, got %s", exp, res)
	}
}

func TestChallenge10(t *testing.T) {
	data := pkg.ReadFile("../testdata/10.txt")
	bytes, err := pkg.Base64ToBytes(data)
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
