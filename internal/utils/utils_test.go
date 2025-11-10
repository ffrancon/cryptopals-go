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

func TestAddPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		expected  []byte
	}{
		{
			name:      "No padding needed",
			input:     []byte("YELLOW SUBMARINE"),
			blockSize: 16,
			expected:  []byte("YELLOW SUBMARINE"),
		},
		{
			name:      "Padding needed",
			input:     []byte("YELLOW"),
			blockSize: 8,
			expected:  []byte("YELLOW\x02\x02"),
		},
		{
			name:      "Empty input",
			input:     []byte(""),
			blockSize: 4,
			expected:  []byte(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddPKCS7Padding(tt.input, tt.blockSize)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("AddPKCS7Padding failed: expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateAndRemovePKCS7Padding(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:        "Valid padding",
			input:       []byte("ICE ICE BABY\x04\x04\x04\x04"),
			expected:    []byte("ICE ICE BABY"),
			expectError: false,
		},
		{
			name:        "Invalid padding length",
			input:       []byte("ICE ICE BABY\x05\x05\x05\x05"),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Invalid padding bytes",
			input:       []byte("ICE ICE BABY\x01\x02\x03\x04"),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Empty input",
			input:       []byte(""),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAndRemovePKCS7Padding(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error but got: %v", err)
				}
				if !bytes.Equal(result, tt.expected) {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}
