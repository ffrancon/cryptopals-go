package tests

import (
	"bytes"
	"ffrancon/cryptopals-go/internal/aes"
	"ffrancon/cryptopals-go/internal/encoding"
	"ffrancon/cryptopals-go/internal/oracle"
	"ffrancon/cryptopals-go/internal/utils"
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
	data := utils.ReadFile("../testdata/10.txt")
	bytes, err := encoding.Base64ToBytes(data)
	if err != nil {
		t.Errorf("error converting base64 to bytes: %v", err)
	}
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	decrypted := aes.AESCBCDecrypt(bytes, key, iv)
	reg := regexp.MustCompile(`You thought that I was weak, Boy, you're dead wrong`)
	if !reg.Match(decrypted) {
		t.Errorf("expected %s, got %s", reg, decrypted)
	}
}

func TestChallenge11(t *testing.T) {
	repeatedBlock := bytes.Repeat([]byte("A"), 64) // 4 blocks of 16 bytes
	input := string(repeatedBlock)
	ecb := 0
	cbc := 0
	for range 200 {
		result := oracle.AESECBOrCBCOracle(input)
		switch result {
		case "ECB":
			ecb++
		case "CBC":
			cbc++
		default:
			t.Errorf("Unexpected result: %s", result)
		}
	}
	// Both modes should be detected (due to random mode selection)
	if ecb == 0 {
		t.Error("ECB mode was never detected, expected some ECB detections")
	}
	if cbc == 0 {
		t.Error("CBC mode was never detected, expected some CBC detections")
	}
	t.Logf("Detection results over 200 iterations: ECB=%d, CBC=%d", ecb, cbc)
}

func TestChallenge12(t *testing.T) {
	decrypted, err := oracle.AESECBOracle()
	if err != nil {
		t.Errorf("Error in AESECBOracle: %v", err)
		return
	}
	expectedSubstring := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if !bytes.Contains(decrypted, []byte(expectedSubstring)) {
		t.Errorf("Decrypted string does not contain expected substring.\nExpected to find: %q\nDecrypted: %q", expectedSubstring, decrypted)
	}
}

func TestChallenge13(t *testing.T) {
	profile, err := oracle.AESECBCutAndPasteAttack("crack@bar.com")
	if err != nil {
		t.Errorf("Error in AESECBCutAndPasteAttack: %v", err)
		return
	}
	profileMap := oracle.QueryStringToMap(profile)
	if profileMap["email"] != "crack@bar.com" {
		t.Errorf("Expected email to be crack@bar.com, got %s", profileMap["email"])
	}
	if profileMap["uid"] != "10" {
		t.Errorf("Expected uid to be 10, got %s", profileMap["uid"])
	}
	// The role should now be "admin" with proper PKCS#7 padding
	if profileMap["role"] != "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" {
		t.Errorf("Expected role to be admin, got %s", profileMap["role"])
	}
}

func TestChallenge14(t *testing.T) {
	// TODO
}

func TestChallenge15(t *testing.T) {
	validPadded := []byte("ICE ICE BABY\x04\x04\x04\x04")
	invalidPadded := []byte("ICE ICE BABY\x05\x05\x05\x05")
	invalidPadded2 := []byte("ICE ICE BABY\x01\x02\x03\x04")

	// Test valid padding
	unpadded, err := utils.ValidateAndRemovePKCS7Padding(validPadded)
	if err != nil {
		t.Errorf("Expected valid padding, got error: %v", err)
	}
	expectedUnpadded := []byte("ICE ICE BABY")
	if !bytes.Equal(unpadded, expectedUnpadded) {
		t.Errorf("Expected unpadded to be %v, got %v", expectedUnpadded, unpadded)
	}

	// Test invalid padding (case 1)
	_, err = utils.ValidateAndRemovePKCS7Padding(invalidPadded)
	if err == nil {
		t.Errorf("Expected error for invalid padding, got nil")
	}

	// Test invalid padding (case 2)
	_, err = utils.ValidateAndRemovePKCS7Padding(invalidPadded2)
	if err == nil {
		t.Errorf("Expected error for invalid padding, got nil")
	}
}
