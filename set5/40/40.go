package main

import (
	"math/big"
)

var (
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

// Cbrt returns the cube root of the given integer using successive approximations.
func Cbrt(z *big.Int) *big.Int {
	prev := new(big.Int)
	guess := new(big.Int).Set(z)
	for prev.Cmp(guess) != 0 {
		prev.Set(guess)
		guess.Exp(guess, two, nil)
		guess.Div(z, guess)
		guess.Add(guess, prev)
		guess.Add(guess, prev)
		guess.Div(guess, three)
	}
	return guess
}

func main() {
}
