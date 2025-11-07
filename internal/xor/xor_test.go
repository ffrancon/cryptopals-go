package xor

import (
	"bytes"
	"testing"
)

func TestXorBytes(t *testing.T) {
	bytes1 := []byte{0x1F, 0x2B, 0x3C}
	bytes2 := []byte{0x0F, 0x1A, 0x2D}
	expected := []byte{0x10, 0x31, 0x11}
	result := XorBytes(bytes1, bytes2)
	if !bytes.Equal(result, expected) {
		t.Errorf("XorBytes failed: expected %v, got %v", expected, result)
	}
}

func TestXorSingleByte(t *testing.T) {
	bytes1 := []byte{0x1F, 0x2B, 0x3C}
	by := byte(0x0F)
	expected := []byte{0x10, 0x24, 0x33}
	result := XorSingleByte(bytes1, by)
	if !bytes.Equal(result, expected) {
		t.Errorf("XorSingleByte failed: expected %v, got %v", expected, result)
	}
}

func TestXorHexStrings(t *testing.T) {
	hex1 := "1f2b3c"
	hex2 := "0f1a2d"
	expected := "103111"
	result := XorHexStrings(hex1, hex2)
	if result != expected {
		t.Errorf("XorHexStrings failed: expected %s, got %s", expected, result)
	}
}

func TestXorRepeatingKey(t *testing.T) {
	bytes1 := []byte{0x1F, 0x2B, 0x3C, 0x4D, 0x5E}
	key := []byte{0x0F, 0x1A}
	expected := []byte{0x10, 0x31, 0x33, 0x57, 0x51}
	result := XorRepeatingKey(bytes1, key)
	if !bytes.Equal(result, expected) {
		t.Errorf("XorRepeatingKey failed: expected %v, got %v", expected, result)
	}
}
