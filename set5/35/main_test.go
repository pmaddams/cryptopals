package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestDH(t *testing.T) {
	p, err := ParseBigInt(dhPrime, 16)
	if err != nil {
		panic(err)
	}
	g, err := ParseBigInt(dhGenerator, 16)
	if err != nil {
		panic(err)
	}
	a, b := DHGenerateKey(p, g), DHGenerateKey(p, g)

	s1 := a.Secret(b.Public())
	s2 := b.Secret(a.Public())

	if !bytes.Equal(s1, s2) {
		t.Errorf(`secrets not equal:
p = %x
g = %x
a = %x
A = %x
b = %x
B = %x
(B^a)%%p = %x
(A^b)%%p = %x`,
			p, g, a.x, a.y, b.x, b.y, s1, s2)
	}
}

func TestPKCS7Pad(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      []byte
	}{
		{
			[]byte{0},
			3,
			[]byte{0, 2, 2},
		},
		{
			[]byte{0, 0},
			3,
			[]byte{0, 0, 1},
		},
		{
			[]byte{0, 0, 0},
			3,
			[]byte{0, 0, 0, 3, 3, 3},
		},
	}
	for _, c := range cases {
		got := PKCS7Pad(c.buf, c.blockSize)
		if !bytes.Equal(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestPKCS7Unpad(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      []byte
	}{
		{
			[]byte{0, 2, 2},
			3,
			[]byte{0},
		},
		{
			[]byte{0, 0, 1},
			3,
			[]byte{0, 0},
		},
		{
			[]byte{0, 0, 0, 3, 3, 3},
			3,
			[]byte{0, 0, 0},
		},
	}
	for _, c := range cases {
		got, _ := PKCS7Unpad(c.buf, c.blockSize)
		if !bytes.Equal(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
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

func TestRandomBytes(t *testing.T) {
	var bufs [][]byte
	for i := 0; i < 5; i++ {
		bufs = append(bufs, RandomBytes(16))
		for j := 0; j < i; j++ {
			if bytes.Equal(bufs[i], bufs[j]) {
				t.Errorf("identical buffers %v and %v", bufs[i], bufs[j])
			}
		}
	}
}
