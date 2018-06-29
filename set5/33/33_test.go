package main

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
)

func TestSecret(t *testing.T) {
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
