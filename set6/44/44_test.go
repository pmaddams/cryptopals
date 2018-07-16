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
	for i := 0; i < 5; i++ {
		want, err := rand.Int(weak, max)
		if err != nil {
			t.Error(err)
		}
		s := insertNewlines(fmt.Sprintf("%b", want))
		got, err := ParseBigInt(s, 2)
		if err != nil {
			t.Error(err)
		}
		if !equal(got, want) {
			t.Errorf("got %v, want %v (binary)", got, want)
		}
		s = insertNewlines(fmt.Sprintf("%o", want))
		got, err = ParseBigInt(s, 8)
		if err != nil {
			t.Error(err)
		}
		if !equal(got, want) {
			t.Errorf("got %v, want %v (octal)", got, want)
		}
		s = insertNewlines(fmt.Sprintf("%d", want))
		got, err = ParseBigInt(s, 10)
		if err != nil {
			t.Error(err)
		}
		if !equal(got, want) {
			t.Errorf("got %v, want %v (decimal)", got, want)
		}
		s = insertNewlines(fmt.Sprintf("%x", want))
		got, err = ParseBigInt(s, 16)
		if err != nil {
			t.Error(err)
		}
		if !equal(got, want) {
			t.Errorf("got %v, want %v (hexadecimal)", got, want)
		}
	}
}
