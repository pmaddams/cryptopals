package main

import (
	"bytes"
	"testing"
)

func TestDH(t *testing.T) {
	p, err := hexToBigInt(dhDefaultP)
	if err != nil {
		panic(err)
	}
	g, err := hexToBigInt(dhDefaultG)
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
