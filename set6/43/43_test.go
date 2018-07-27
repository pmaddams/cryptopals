package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestDSA(t *testing.T) {
	p, err := ParseBigInt(dsaPrime, 16)
	if err != nil {
		panic(err)
	}
	q, err := ParseBigInt(dsaSubprime, 16)
	if err != nil {
		panic(err)
	}
	g, err := ParseBigInt(dsaGenerator, 16)
	if err != nil {
		panic(err)
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	h := sha256.New()
	for i := 0; i < 5; i++ {
		h.Reset()
		n := int64(16 + weak.Intn(16))
		io.CopyN(h, weak, n)
		sum1 := h.Sum([]byte{})

		priv := DSAGenerateKey(p, q, g)
		r, s := DSASign(priv, sum1)
		if !DSAVerify(priv.Public(), sum1, r, s) {
			t.Error("verification failed")
		}
		io.CopyN(h, weak, n)
		sum2 := h.Sum([]byte{})
		if DSAVerify(priv.Public(), sum2, r, s) {
			t.Error("verified incorrect checksum")
		}
		r, err := rand.Int(weak, priv.q)
		if err != nil {
			panic(err)
		}
		s, err = rand.Int(weak, priv.q)
		if err != nil {
			panic(err)
		}
		if DSAVerify(priv.Public(), sum1, r, s) {
			t.Error("verified incorrect signature")
		}
	}
}

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
			panic(err)
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
