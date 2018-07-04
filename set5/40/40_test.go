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
		root := Cbrt(want)
		got := new(big.Int).Exp(root, three, nil)
		if want.Cmp(got) != 0 {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
