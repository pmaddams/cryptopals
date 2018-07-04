package main

import (
	"crypto/rand"
	"math"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func TestCbrt(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	max := big.NewInt(math.MaxInt64)
	for i := 0; i < 10; i++ {
		want, err := rand.Int(weak, max)
		if err != nil {
			t.Error(err)
		}
		cube := new(big.Int).Exp(want, three, nil)
		got := Cbrt(cube)
		if got.Cmp(want) != 0 {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
