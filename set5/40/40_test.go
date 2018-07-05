package main

import (
	"crypto/rand"
	"math"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func TestRSA(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 16)
	for i := 0; i < 5; i++ {
		priv, err := RSAGenerateKey(3, 128)
		if err != nil {
			t.Error(err)
		}
		weak.Read(buf)
		ciphertext, err := RSAEncrypt(&priv.RSAPublicKey, buf)
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
			t.Errorf("got %x, want %x", got, want)
		}
	}
}

func TestCbrt(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	max := big.NewInt(math.MaxInt64)
	for i := 0; i < 10; i++ {
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
