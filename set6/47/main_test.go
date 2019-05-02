package main

import (
	"bytes"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestRSACryptPKCS1v15(t *testing.T) {
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
		ciphertext, err := RSAEncryptPKCS1v15(priv.Public(), buf)
		if err != nil {
			t.Error(err)
		}
		plaintext, err := RSADecryptPKCS1v15(priv, ciphertext)
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

func TestPKCS1v15CryptPadUnpad(t *testing.T) {
	priv, err := RSAGenerateKey(3, 256)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 5; i++ {
		want := make([]byte, weak.Intn(size(priv.n)-10))
		weak.Read(want)

		buf, err := PKCS1v15CryptPad(want, size(priv.n))
		if err != nil {
			t.Fatal(err)
		}
		got, err := PKCS1v15CryptUnpad(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
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
