package main

import (
	"bytes"
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

func TestRightCopy(t *testing.T) {
	cases := []struct {
		dst, src, want []byte
	}{
		{
			[]byte{0},
			[]byte{},
			[]byte{0},
		},
		{
			[]byte{0, 1, 2},
			[]byte{3},
			[]byte{0, 1, 3},
		},
		{
			[]byte{1, 2, 3},
			[]byte{4, 5, 6},
			[]byte{4, 5, 6},
		},
	}
	for _, c := range cases {
		RightCopy(c.dst, c.src)
		if !bytes.Equal(c.dst, c.want) {
			t.Errorf("got %v, want %v", c.dst, c.want)
		}
	}
}
