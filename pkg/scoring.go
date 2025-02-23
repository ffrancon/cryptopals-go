package pkg

import (
	"math"
	"regexp"
)

var charFrequencyTable = map[byte]float64{
	'A':  0.08167, // A
	'B':  0.01492, // B
	'C':  0.02782, // C
	'D':  0.04253, // D
	'E':  0.12702, // E
	'F':  0.02228, // F
	'G':  0.02015, // G
	'H':  0.06094, // H
	'I':  0.06966, // I
	'J':  0.00153, // J
	'K':  0.00772, // K
	'L':  0.04025, // L
	'M':  0.02406, // M
	'N':  0.06749, // N
	'O':  0.07507, // O
	'P':  0.01929, // P
	'Q':  0.00095, // Q
	'R':  0.05987, // R
	'S':  0.06327, // S
	'T':  0.09056, // T
	'U':  0.02758, // U
	'V':  0.00978, // V
	'W':  0.02360, // W
	'X':  0.00150, // X
	'Y':  0.01974, // Y
	'Z':  0.00074, // Z
	' ':  0.13000, // Space
	'!':  0.01000, // !
	'?':  0.01000, // ?
	'"':  0.01000, // "
	'\'': 0.01000, // '
	',':  0.01000, // ,
	'.':  0.01000, // .
	':':  0.01000, // :
	';':  0.01000, // ;
	'-':  0.01000, // -
	'\n': 0.01000, // \n
	'\r': 0.01000, // \r
	'0':  0.01000, // 0
	'1':  0.01000, // 1
	'2':  0.01000, // 2
	'3':  0.01000, // 3
	'4':  0.01000, // 4
	'5':  0.01000, // 5
	'6':  0.01000, // 6
	'7':  0.01000, // 7
	'8':  0.01000, // 8
	'9':  0.01000, // 9
}

var nonEnglishCharRegexp = regexp.MustCompile(`[^a-zA-Z0-9\s\r!?":;.,'-]`)

func ScoringEnglish(bytes []byte) (score float64) {
	// eliminate non-english characters
	if len(nonEnglishCharRegexp.FindAllIndex(bytes, -1)) > 0 {
		return -1
	}
	charHits := make(map[byte]int)
	for _, byte := range bytes {
		// convert lowercase to uppercase
		if byte >= 97 && byte <= 122 {
			charHits[byte-32] = charHits[byte-32] + 1
		} else {
			charHits[byte] = charHits[byte] + 1
		}
	}
	// Chi-square test
	for char, avgFrequency := range charFrequencyTable {
		occ := float64(charHits[char])
		expOcc := float64(len(bytes)) * avgFrequency
		score += math.Pow(occ-expOcc, 2) / expOcc
	}
	return score
}

func IsBetterEnglishScore(score, bestScore float64) bool {
	return bestScore == -1 || (score >= 0 && score < bestScore)
}

func ScoringECBMode(bytes []byte) int {
	score := 0
	blocks := ChunkBytes(bytes, 16)
	areBlocksChecked := map[string]bool{}
	for x, base := range blocks {
		if exists := areBlocksChecked[string(base)]; !exists {
			for y, compared := range blocks {
				if exists := areBlocksChecked[string(compared)]; exists || x == y {
					continue
				}
				if string(base) == string(compared) {
					score++
				}
			}
			areBlocksChecked[string(base)] = true
		}
	}
	return score
}
