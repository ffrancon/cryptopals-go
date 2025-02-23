package pkg

import (
	"fmt"
)

func XorBytes(bytes1, bytes2 []byte) (bytes []byte) {
	bytes = make([]byte, len(bytes1))
	for i := range bytes {
		bytes[i] = bytes1[i] ^ bytes2[i]
	}
	return bytes
}

func XorSingleByte(bytes []byte, by byte) []byte {
	xor := make([]byte, len(bytes))
	for i := range bytes {
		xor[i] = bytes[i] ^ by
	}
	return xor
}

func XorHexStrings(string1, string2 string) (result string) {
	bytes1 := HexStrToBytes(string1)
	bytes2 := HexStrToBytes(string2)
	if len(bytes1) != len(bytes2) {
		fmt.Println("buffers are not of the same length")
		return ""
	}
	bytes := XorBytes(bytes1, bytes2)
	return BytesToHexStr(bytes)
}

func XorRepeatingKey(bytes, key []byte) []byte {
	xor := make([]byte, len(bytes))
	for i := range bytes {
		xor[i] = bytes[i] ^ key[i%len(key)]
	}
	return xor
}
