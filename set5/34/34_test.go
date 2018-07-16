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
	p, err := ParseBigInt(dhDefaultP, 16)
	if err != nil {
		panic(err)
	}
	g, err := ParseBigInt(dhDefaultG, 16)
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

func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
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
