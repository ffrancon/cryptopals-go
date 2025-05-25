package pkg

import (
	"encoding/base64"
	"encoding/hex"
)

func HexStrToBytes(str string) ([]byte, error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return bytes, err
}

func BytesToHexStr(data []byte) string {
	return hex.EncodeToString(data)
}

func HexStrToBase64(str string) ([]byte, error) {
	data, err := HexStrToBytes(str)
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(bytes, data)
	return bytes, nil
}

func Base64ToBytes(data string) ([]byte, error) {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
