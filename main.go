package main

import (
	"ffrancon/cryptopals-go/pkg"
	"fmt"
)

// [49 246 193 241 155 103 45 91 5 172 204 196 147 234 106 133]
var key = []byte{49, 246, 193, 241, 155, 103, 45, 91, 5, 172, 204, 196, 147, 234, 106, 133}
var base64StrToAppend = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func ora(plaintext string) []byte {
	bytesToAppend := pkg.Base64ToBytes(base64StrToAppend)
	bytes := make([]byte, 0)
	bytes = append(bytes, []byte(plaintext)...)
	bytes = append(bytes, bytesToAppend...)

	return pkg.AESECBEncrypt(bytes, key)

}

func main() {
	output := ora("Hello, world!")
	fmt.Println(output)
}
