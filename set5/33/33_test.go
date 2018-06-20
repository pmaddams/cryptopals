package main

import (
	"bytes"
	"testing"
)

func TestSecret(t *testing.T) {
	a, b := DHGenerateKey(), DHGenerateKey()

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
			prime, generator, a.n, a.Public(), b.n, b.Public(), s1, s2)
	}
}
