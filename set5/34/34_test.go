package main

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
)

func TestSecret(t *testing.T) {
	p, ok := new(big.Int).SetString(strings.Replace(defaultP, "\n", "", -1), 16)
	if !ok {
		panic("invalid parameters")
	}
	g, ok := new(big.Int).SetString(defaultG, 16)
	if !ok {
		panic("invalid parameters")
	}
	for i := 0; i < 5; i++ {
		a, b := DHGenerateKey(p, g), DHGenerateKey(p, g)

		s1 := a.Secret(b.Public())
		s2 := b.Secret(a.Public())

		if !bytes.Equal(s1, s2) {
			t.Errorf(`Secrets not equal:
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
}
