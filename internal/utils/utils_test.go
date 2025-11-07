package utils

import (
	"bytes"
	"testing"
)

func TestChunkBytes(t *testing.T) {
	data := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	blockSize := 16
	expected := [][]byte{
		[]byte("YELLOW SUBMARINE"),
		[]byte("YELLOW SUBMARINE"),
	}
	result := ChunkBytes(data, blockSize)
	if len(result) != len(expected) {
		t.Errorf("ChunkBytes failed: expected %d chunks, got %d", len(expected), len(result))
		return
	}
	for i := range expected {
		if !bytes.Equal(result[i], expected[i]) {
			t.Errorf("ChunkBytes failed at chunk %d: expected %v, got %v", i, expected[i], result[i])
		}
	}
}

func TestFlattenBytesChunks(t *testing.T) {
	chunks := [][]byte{
		[]byte("YELLOW "),
		[]byte("SUBMARINE"),
	}
	expected := []byte("YELLOW SUBMARINE")
	result := FlattenBytesChunks(chunks)
	if !bytes.Equal(result, expected) {
		t.Errorf("FlattenBytesChunks failed: expected %v, got %v", expected, result)
	}
}

func TestTransposeBytesChunks(t *testing.T) {
	chunks := [][]byte{
		[]byte("ABC"),
		[]byte("DEF"),
		[]byte("GHI"),
	}
	expected := [][]byte{
		[]byte("ADG"),
		[]byte("BEH"),
		[]byte("CFI"),
	}
	result := TransposeBytesChunks(chunks)
	if len(result) != len(expected) {
		t.Errorf("TransposeBytesChunks failed: expected %d transposed chunks, got %d", len(expected), len(result))
		return
	}
	for i := range expected {
		if !bytes.Equal(result[i], expected[i]) {
			t.Errorf("TransposeBytesChunks failed at chunk %d: expected %v, got %v", i, expected[i], result[i])
		}
	}
}
