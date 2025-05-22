package pkg

import (
	"encoding/base64"
	"encoding/hex"
	"ffrancon/cryptopals/utils"
)

func HexStrToBytes(str string) []byte {
	bytes, err := hex.DecodeString(str)
	utils.Check(err)
	return bytes
}

func BytesToHexStr(data []byte) string {
	return hex.EncodeToString(data)
}

func HexStrToBase64(str string) []byte {
	data := HexStrToBytes(str)
	bytes := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(bytes, data)
	return bytes
}

func Base64ToBytes(data string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(data)
	utils.Check(err)
	return bytes
}
