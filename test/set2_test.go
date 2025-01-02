package tests

import (
	"ffrancon/cryptopals-go/pkg"
	"testing"
)

func TestChallenge9(t *testing.T) {
	res := pkg.AddPKCS7Padding([]byte("YELLOW SUBMARINE"), 20)
	exp := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(res) != exp {
		t.Errorf("expected %s, got %s", exp, res)
	}
}
