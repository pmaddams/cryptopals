package main

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	weak "math/rand"
	"testing"
	"time"
)

func TestDSA(t *testing.T) {
	p, err := hexToBigInt(dsaDefaultP)
	if err != nil {
		panic(err)
	}
	q, err := hexToBigInt(dsaDefaultQ)
	if err != nil {
		panic(err)
	}
	g, err := hexToBigInt(dsaDefaultG)
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
