package main

import (
	"bytes"
	"math/big"
	weak "math/rand"
	"strings"
	"testing"
	"time"
)

func TestDH(t *testing.T) {
	p, ok := new(big.Int).SetString(strings.Replace(defaultPrime, "\n", "", -1), 16)
	if !ok || !p.ProbablyPrime(0) {
		panic("invalid prime")
	}
	g, ok := new(big.Int).SetString(defaultGenerator, 16)
	if !ok {
		panic("invalid generator")
	}
	a, b := DHGenerateKey(p, g), DHGenerateKey(p, g)

	s1 := a.Secret(&b.DHPublicKey)
	s2 := b.Secret(&a.DHPublicKey)

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
			p, g, a.priv, a.pub, b.priv, b.pub, s1, s2)
	}
}

func TestRandomBytes(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	n := weak.Intn(1024)

	var bufs [][]byte
	for i := 0; i < 5; i++ {
		buf := RandomBytes(n)
		if len(buf) != n {
			t.Errorf("got length %v, want %v", len(buf), n)
		}
		bufs = append(bufs, buf)
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
