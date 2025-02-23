package pkg

import (
	"errors"
	"math/rand"
	"os"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func CalculateHammingDistance(bytes1, bytes2 []byte) (hammingDistance int, err error) {
	if len(bytes1) != len(bytes2) {
		return -1, errors.New("byte arrays are not of the same length")
	}
	for i, byte := range bytes1 {
		xor := int(byte ^ bytes2[i])
		for xor > 0 {
			hammingDistance += xor & 1
			xor >>= 1
		}
	}
	return hammingDistance, nil
}

func CalculateAverageHammingDistance(bytes []byte, bufferSize int) (averageHammingDistance float64) {
	buffers := make([]float64, len(bytes)/bufferSize-1)
	for i := 0; i < len(buffers); i++ {
		hammingDistance, _ := CalculateHammingDistance(bytes[bufferSize*i:bufferSize*(i+1)], bytes[bufferSize*(i+1):bufferSize*(i+2)])
		normalizedHammingDistance := float64(hammingDistance) / float64(bufferSize)
		buffers[i] = normalizedHammingDistance
	}
	total := 0.0
	for _, normalizedHammingDistance := range buffers {
		total += normalizedHammingDistance
	}
	return total / float64(len(buffers))
}

func DetermineBestKeySize(bytes []byte, min, max int) (result int) {
	hammingDistance := float64(-1)
	for i := min; i < max; i++ {
		averageHammingDistance := CalculateAverageHammingDistance(bytes, i)
		if hammingDistance == -1 || averageHammingDistance < hammingDistance {
			hammingDistance = averageHammingDistance
			result = i
		}
	}
	return result
}

func ReadFile(path string) string {
	bytes, err := os.ReadFile(path)
	Check(err)
	return string(bytes)
}

// [1, 2, 3, 4, 5, 6, 7, 8] -> [[1, 2], [3, 4], [5, 6], [7, 8]]
func ChunkBytes(bytes []byte, size int) (chunks [][]byte) {
	end := len(bytes)
	for i := 0; i < end; i += size {
		to := i + size
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
	transposedChunks := make([][]byte, singleChunkLength)
	// create a new array with the length of the first chunk
	for x := 0; x < singleChunkLength; x++ {
		transposedChunks[x] = make([]byte, chunksLength)
		// iterate over the chunks and add the byte to the new array
		for y := 0; y < chunksLength; y++ {
			if x < len(chunks[y]) {
				transposedChunks[x][y] = chunks[y][x]
			}
		}
	}
	return transposedChunks
}

func AddPKCS7Padding(bytes []byte, size int) []byte {
	if len(bytes)%size == 0 {
		return bytes
	}
	paddingLength := size - len(bytes)%size
	for i := 0; i < paddingLength; i++ {
		bytes = append(bytes, byte(paddingLength))
	}
	return bytes
}

func GenerateRandomBytes(size int) []byte {
	bytes := make([]byte, size)
	for i := 0; i < size; i++ {
		bytes[i] = byte(rand.Intn(256))
	}
	return bytes
}
