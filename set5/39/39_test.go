package main

import (
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
