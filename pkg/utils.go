package pkg

import (
	"errors"
	"fmt"
	"math"
	"os"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func ComputeHammingDistance(bytes1, bytes2 []byte) (d int, e error) {
	if len(bytes1) != len(bytes2) {
		return -1, errors.New("byte arrays are not of the same length")
	}
	for i, b := range bytes1 {
		xor := int(b ^ bytes2[i])
		for xor > 0 {
			d += xor & 1
			xor >>= 1
		}
	}
	return d, nil
}

func ComputeNormalizedHammingDistance(bytes []byte, s int) float64 {
	raw := make([]float64, len(bytes)/s-1)
	for i := 0; i < len(raw); i++ {
		d, _ := ComputeHammingDistance(bytes[s*i:s*(i+1)], bytes[s*(i+1):s*(i+2)])
		n := float64(d) / float64(s)
		raw[i] = n
	}
	total := 0.0
	for _, r := range raw {
		total += r
	}
	avg := total / float64(len(raw))
	return avg
}

func DetermineBestKeySize(bytes []byte, min, max int) (s int) {
	d := float64(-1)
	for i := min; i < max; i++ {
		nd := ComputeNormalizedHammingDistance(bytes, i)
		if d == -1 || nd < d {
			d = nd
			s = i
		}
	}
	return s
}

func ReadFile(path string) string {
	bytes, err := os.ReadFile(path)
	Check(err)
	return string(bytes)
}

// [1, 2, 3, 4, 5, 6, 7, 8] -> [[1, 2], [3, 4], [5, 6], [7, 8]]
func ChunkBytes(bytes []byte, s int) (chunks [][]byte) {
	end := len(bytes)
	for i := 0; i < end; i += s {
		to := i + s
		if to > end {
			to = end
		}
		chunks = append(chunks, bytes[i:to])
	}
	return chunks
}

// [[1, 2], [3, 4], [5, 6], [7]] -> [[1, 3, 5, 7], [2, 4, 6,]]
func TransposeBytesChunks(chunks [][]byte) [][]byte {
	chunksLength := len(chunks)
	singleChunkLength := len(chunks[0])
	transposed := make([][]byte, singleChunkLength)
	// create a new array with the length of the first chunk
	for x := 0; x < singleChunkLength; x++ {
		transposed[x] = make([]byte, chunksLength)
		// iterate over the chunks and add the byte to the new array
		for y := 0; y < chunksLength; y++ {
			if x < len(chunks[y]) {
				transposed[x][y] = chunks[y][x]
			}
		}
	}
	return transposed
}

func CountByteOccurence(bytes []byte) float64 {
	r := 0.0
	c := 0.0
	alr := map[byte]bool{}
	for i, refByte := range bytes {
		// if the byte has not been already counted
		if !alr[refByte] {
			alr[refByte] = true
			// iterate over the rest of the bytes
			for _, toCompareByte := range bytes[i+1:] {
				if refByte == toCompareByte {
					c++
				}
			}
		} else {
			continue
		}
		r += math.Pow(2, c)
		c = 0.0
	}
	fmt.Printf("Score: %f\n", r)
	return r
}
