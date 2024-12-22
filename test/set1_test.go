package set1

import (
	"ffrancon/cryptopals-go/pkg"
	"regexp"
	"testing"
)

func TestChallenge1(t *testing.T) {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	exp := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	res := pkg.HexStrToBase64(hex)
	if string(res) != exp {
		t.Errorf("expected %s, got %s", exp, res)
	}
}

func TestChallenge2(t *testing.T) {
	buf1 := "1c0111001f010100061a024b53535009181c"
	buf2 := "686974207468652062756c6c277320657965"
	exp := "746865206b696420646f6e277420706c6179"
	res := pkg.XorBuffers(buf1, buf2)
	if res != exp {
		t.Errorf("expected %s, got %s", exp, res)
	}
}

func TestChallenge3(t *testing.T) {
	bytes := pkg.HexStrToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	m := "Cooking MC's like a pound of bacon"
	key := byte(88)
	res := pkg.DecryptXorSingleByte(bytes, 0)
	if string(res.Decrypted[:]) != m && res.Key != key {
		t.Errorf("expected %s & %d, got %s & %d", m, key, res.Decrypted, res.Key)
	}
}

func TestChallenge4(t *testing.T) {
	res := pkg.DecryptXorSingleByteFromBatchFile("../data/4.txt")
	if string(res.Decrypted[:]) != "Now that the party is jumping\n" && res.Key != byte(53) {
		t.Errorf("expected %s & %d, got %s & %d", "Now that the party is jumping\n", byte(53), res.Decrypted, res.Key)
	}
}

func TestChallenge5(t *testing.T) {
	xor := pkg.XorRepeatingKey([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE"))
	res := pkg.BytesToHexStr(xor)
	exp := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if res != exp {
		t.Errorf("expected %s, got %s", exp, res)
	}
}

func TestChallenge6(t *testing.T) {
	data := pkg.ReadFile("../data/6.txt")
	bytes := pkg.Base64ToBytes(data)
	ks := pkg.DetermineBestKeySize(bytes, 2, 40)
	if ks != 29 {
		t.Errorf("expected %d, got %d", 29, ks)
	}
	chunks := pkg.ChunkBytes(bytes, ks)
	transposed := pkg.TransposeBytesChunks(chunks)
	key := make([]byte, ks)
	for x := range transposed {
		m := pkg.DecryptXorSingleByte(transposed[x], x)
		key[x] = m.Key
	}
	if string(key) != "Terminator X: Bring the noise" {
		t.Errorf("expected %s, got %s", "Terminator X: Bring the noise", string(key))
	}
}

func TestChallenge7(t *testing.T) {
	data := pkg.ReadFile("../data/7.txt")
	bytes := pkg.Base64ToBytes(data)
	key := []byte("YELLOW SUBMARINE")
	decrypted := pkg.AesECBDecrypt(bytes, key)
	reg := regexp.MustCompile(`You thought that I was weak, Boy, you're dead wrong`)
	if !reg.Match(decrypted) {
		t.Errorf("expected %s, got %s", reg, decrypted)
	}
}
