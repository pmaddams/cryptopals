package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func insertNewlines(s string) string {
	var runes []rune
	for _, r := range s {
		runes = append(runes, r)
		if weak.Intn(5) == 0 {
			runes = append(runes, '\n')
		}
	}
	return string(runes)
}

func TestParseBigInt(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	max := big.NewInt(math.MaxInt64)
	cases := []struct {
		format string
		base   int
	}{
		{"%b", 2},
		{"%o", 8},
		{"%d", 10},
		{"%x", 16},
	}
	for i := 0; i < 5; i++ {
		want, err := rand.Int(weak, max)
		if err != nil {
			t.Error(err)
		}
		for _, c := range cases {
			s := insertNewlines(fmt.Sprintf(c.format, want))
			got, err := ParseBigInt(s, c.base)
			if err != nil {
				t.Error(err)
			}
			if !equal(got, want) {
				t.Errorf("got %v, want %v (base %v)", got, want, c.base)
			}
		}
	}
}
