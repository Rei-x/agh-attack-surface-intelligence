package domain

import "testing"

func TestCombineFactorsDiminishingReturns(t *testing.T) {
	score, fs := CombineFactors([]InterestingnessFactor{
		{Reason: "admin", Weight: 35},
		{Reason: "kev", Weight: 60},
		{Reason: "headers", Weight: 5, Kind: FactorKindHygiene},
	})
	// 60, then 35% of 40 = 14 -> 74, then 5% of 26 = 1.3 -> 75.
	if score != 75 || fs[0].Reason != "kev" || fs[0].Points != 60 || fs[1].Points != 14 || fs[2].Points != 1 {
		t.Fatalf("score %d factors %+v", score, fs)
	}
	again, fs2 := CombineFactors(fs)
	if again != score || len(fs2) != len(fs) || fs2[1].Points != 14 {
		t.Fatalf("not idempotent: %d %+v", again, fs2)
	}
	// Legacy stored factors (Points only) use Points as the weight.
	if s, _ := CombineFactors([]InterestingnessFactor{{Reason: "old", Points: 20}}); s != 20 {
		t.Fatalf("legacy factor scored %d", s)
	}
}

func TestCombineFactorsHygieneCap(t *testing.T) {
	var fs []InterestingnessFactor
	for _, r := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		fs = append(fs, InterestingnessFactor{Reason: r, Weight: 8, Kind: FactorKindHygiene})
	}
	score, out := CombineFactors(fs)
	sum := 0
	for _, f := range out {
		sum += f.Points
	}
	if score != HygieneCap || sum != score {
		t.Fatalf("eight hygiene findings scored %d (points %d), want the cap %d", score, sum, HygieneCap)
	}
}

func TestScoreSeverityBands(t *testing.T) {
	for score, want := range map[int]string{95: "Critical", 90: "Critical", 75: "High", 70: "High", 50: "Medium", 30: "Low", 12: "Info"} {
		if got := ScoreSeverity(score); got != want {
			t.Errorf("ScoreSeverity(%d) = %s, want %s", score, got, want)
		}
	}
}
