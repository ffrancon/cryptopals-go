package main

import (
	"bufio"
	"ffrancon/cryptopals-go/pkg"
	"os"
)

func main() {
	file, err := os.Open("data/8.txt")
	pkg.Check(err)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := make([][]byte, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Bytes())
	}
	for _, l := range lines {
		pkg.CountByteOccurence(l)
	}
}
