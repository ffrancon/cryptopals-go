package scoring

import (
	"testing"
)

func TestIsBetterEnglishScore(t *testing.T) {
	score1 := 75.0
	score2 := 50.0
	score3 := -1.0

	if IsBetterEnglishScore(score1, score2) {
		t.Errorf("Expected score1 to be better than score2")
	}
	if !IsBetterEnglishScore(score2, score1) {
		t.Errorf("Expected score2 to not be better than score1")
	}
	if !IsBetterEnglishScore(score1, score3) {
		t.Errorf("Expected score1 to be better than score3")
	}
	if IsBetterEnglishScore(score3, score1) {
		t.Errorf("Expected score3 to not be better than score1")
	}
}
