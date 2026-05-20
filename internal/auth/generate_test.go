package auth

import (
	"regexp"
	"testing"
)

var sixDigitRe = regexp.MustCompile(`^\d{6}$`)

func TestGeneratePassword_SixDigits(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword: %v", err)
		}
		if !sixDigitRe.MatchString(pw) {
			t.Fatalf("password %q does not match /^\\d{6}$/", pw)
		}
	}
}

// TestGeneratePassword_Distribution does a lightweight sanity check that
// crypto/rand is actually feeding GeneratePassword — we draw a few
// thousand samples and assert at least 1000 distinct values appear and
// each decimal digit appears in every position at least once.
//
// This is *not* a strict uniformity test (10^6 space, 5000 draws — too
// few to test strict uniformity reliably). It catches "function always
// returns 000000" style bugs without becoming flaky.
func TestGeneratePassword_Distribution(t *testing.T) {
	t.Parallel()
	const draws = 5000
	seen := make(map[string]struct{}, draws)
	digitInPos := [6][10]bool{}
	for i := 0; i < draws; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword: %v", err)
		}
		seen[pw] = struct{}{}
		for pos, r := range pw {
			digitInPos[pos][r-'0'] = true
		}
	}
	if len(seen) < 1000 {
		t.Errorf("only %d distinct passwords in %d draws — generator looks broken", len(seen), draws)
	}
	for pos := 0; pos < 6; pos++ {
		for d := 0; d < 10; d++ {
			if !digitInPos[pos][d] {
				t.Errorf("digit %d never appeared in position %d across %d draws", d, pos, draws)
			}
		}
	}
}
