package main

import (
	"crypto/rand"
	"math"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestRSA(t *testing.T) {
	const (
		exponent = 3
		bits     = 256
	)
	buf := make([]byte, 16)
	for i := 0; i < 5; i++ {
		priv, err := RSAGenerateKey(exponent, bits)
		if err != nil {
			t.Error(err)
		}
		if n := priv.n.BitLen(); n != bits {
			t.Errorf("got bit size %v, want %v", n, bits)
		}
		weak.Read(buf)
		ciphertext, err := RSAEncrypt(priv.Public(), buf)
		if err != nil {
			t.Error(err)
		}
		plaintext, err := RSADecrypt(priv, ciphertext)
		if err != nil {
			t.Error(err)
		}
		want := new(big.Int).SetBytes(buf)
		got := new(big.Int).SetBytes(plaintext)
		if !equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestCbrt(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	max := big.NewInt(math.MaxInt64)
	for i := 0; i < 5; i++ {
		want, err := rand.Int(weak, max)
		if err != nil {
			t.Error(err)
		}
		cube := new(big.Int).Exp(want, three, nil)
		got := Cbrt(cube)
		if !equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
