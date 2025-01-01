package main

import (
	"bufio"
	"ffrancon/cryptopals-go/pkg"
	"fmt"
	"os"
)

func main() {
	file, err := os.Open("data/8.txt")
	pkg.Check(err)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := make([][]byte, 0)
	for scanner.Scan() {
		txt := scanner.Text()
		lines = append(lines, pkg.HexStrToBytes(txt))
	}
	score := 0
	winner := []byte{}
	index := 0
	for i, l := range lines {
		lineScore := pkg.ScoringECBMode(l)
		if lineScore > score {
			score = lineScore
			winner = l
			index = i
		}
	}
	fmt.Printf("winner: %s with score: %d at index: %d\n", winner, score, index)
}
