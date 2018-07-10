package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"math"
	"math/big"
	weak "math/rand"
	"testing"
	"time"
)

func TestRSA(t *testing.T) {
	const (
		exponent = 3
		bits     = 256
	)
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
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
			t.Errorf("got %x, want %x", got, want)
		}
	}
}

func TestPKCS1v15SignaturePadUnpad(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 16)
	for _, id := range []crypto.Hash{
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	} {
		weak.Read(buf)
		h := id.New()
		h.Write(buf)
		want := h.Sum([]byte{})
		size := 1024 + weak.Intn(1024)
		tmp, err := PKCS1v15SignaturePad(id, want, size)
		if err != nil {
			t.Error(err)
		}
		got, err := PKCS1v15SignatureUnpad(id, tmp)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	}
}

func TestRSASignVerify(t *testing.T) {
	const (
		exponent = 3
		bits     = 768
	)
	priv, err := RSAGenerateKey(exponent, bits)
	if err != nil {
		t.Error(err)
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 16)
	weak.Read(buf)
	for _, id := range []crypto.Hash{
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	} {
		h := id.New()
		h.Write(buf)
		sum := h.Sum([]byte{})
		sig, err := RSASign(priv, id, sum)
		if err != nil {
			t.Error(err)
		}
		if err := RSAVerify(priv.Public(), id, sum, sig); err != nil {
			t.Error(err)
		}
	}
}

func TestRSAVerifyWeak(t *testing.T) {
	const (
		exponent = 3
		bits     = 768
	)
	priv, err := RSAGenerateKey(exponent, bits)
	if err != nil {
		t.Error(err)
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 16)
	weak.Read(buf)
	for _, id := range []crypto.Hash{
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	} {
		h := id.New()
		h.Write(buf)
		sum := h.Sum([]byte{})
		sig, err := RSASign(priv, id, sum)
		if err != nil {
			t.Error(err)
		}
		if err := RSAVerifyWeak(priv.Public(), id, sum, sig); err != nil {
			t.Error(err)
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
