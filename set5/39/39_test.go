package main

import (
	"bytes"
	weak "math/rand"
	"testing"
	"time"
)

func TestRSA(t *testing.T) {
	priv, err := RSAGenerateKey(1024)
	if err != nil {
		t.Error(err)
	}
	want := make([]byte, 16)
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	for i := 0; i < 5; i++ {
		weak.Read(want)
		ciphertext, err := RSAEncrypt(&priv.RSAPublicKey, want)
		if err != nil {
			t.Error(err)
		}
		got, err := RSADecrypt(priv, ciphertext)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("got %x, want %x", got, want)
		}
	}
}
