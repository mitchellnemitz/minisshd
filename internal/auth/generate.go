package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// passwordSpace is 10^6 — six decimal digits.
var passwordSpace = big.NewInt(1_000_000)

// GeneratePassword returns a fresh six-digit numeric password drawn from
// crypto/rand. The output always has exactly six characters; values
// smaller than 100000 are zero-padded so timing analysis on the printed
// banner cannot distinguish "small" from "large" passwords by line
// length. See spec §2 step 8.
func GeneratePassword() (string, error) {
	n, err := rand.Int(rand.Reader, passwordSpace)
	if err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
