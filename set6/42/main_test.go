package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	_ "crypto/sha256"
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

func TestPKCS1v15SignaturePadUnpad(t *testing.T) {
	buf := make([]byte, 16)
	for _, id := range []crypto.Hash{crypto.SHA224, crypto.SHA256} {
		for i := 0; i < 5; i++ {
			weak.Read(buf)
			h := id.New()
			h.Write(buf)
			want := h.Sum([]byte{})
			size := 512 + weak.Intn(512)
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
}

func TestRSASignVerify(t *testing.T) {
	const (
		exponent = 3
		bits     = 512
	)
	priv, err := RSAGenerateKey(exponent, bits)
	if err != nil {
		t.Error(err)
	}
	buf := make([]byte, 16)
	var id crypto.Hash
	for i := 0; i < 5; i++ {
		weak.Read(buf)
		if weak.Intn(2) == 0 {
			id = crypto.SHA224
		} else {
			id = crypto.SHA256
		}
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
		bits     = 512
	)
	priv, err := RSAGenerateKey(exponent, bits)
	if err != nil {
		t.Error(err)
	}
	buf := make([]byte, 16)
	var id crypto.Hash
	for i := 0; i < 5; i++ {
		weak.Read(buf)
		if weak.Intn(2) == 0 {
			id = crypto.SHA224
		} else {
			id = crypto.SHA256
		}
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
	for i := 0; i < 10; i++ {
		want, err := rand.Int(weak, max)
		if err != nil {
			panic(err)
		}
		cube := new(big.Int).Exp(want, three, nil)
		got := Cbrt(cube)
		if !equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
