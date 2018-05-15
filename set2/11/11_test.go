package main

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"testing"
)

func TestRandomCipher(t *testing.T) {
	cases := []cipher.Block{}
	for i := 0; i < 5; i++ {
		cases = append(cases, RandomCipher())
		for j := 0; j < i; j++ {
			if reflect.DeepEqual(cases[i], cases[j]) {
				t.Errorf("RandomCipher created identical ciphers %v and %v",
					cases[i], cases[j])
			}
		}
	}
}

func TestRandomEncrypter(t *testing.T) {
	cases := []cipher.BlockMode{}
	for i := 0; i < 10; i++ {
		cases = append(cases, RandomEncrypter())
	}
	_, isECB := cases[0].(ecbEncrypter)
	for i := 1; i < 10; i++ {
		if _, ok := cases[i].(ecbEncrypter); ok != isECB {
			return
		}
	}
	t.Error("RandomEncrypter created the same block mode 10 times")
}

func TestRandomBytes(t *testing.T) {
	cases := []struct {
		min, max int
	}{
		{0, 0},
		{5, 10},
		{20, 30},
	}
	for _, c := range cases {
		got := RandomBytes(c.min, c.max)
		if len(got) < c.min || len(got) > c.max {
			t.Errorf("RandomBytes(%v, %v) == %v, length out of range",
				c.min, c.max, got)
		}
	}
}

func TestPKCS7Pad(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      []byte
	}{
		{
			[]byte{0},
			3,
			[]byte{0, 2, 2},
		},
		{
			[]byte{0, 0},
			3,
			[]byte{0, 0, 1},
		},
		{
			[]byte{0, 0, 0},
			3,
			[]byte{0, 0, 0, 3, 3, 3},
		},
	}
	for _, c := range cases {
		got := PKCS7Pad(c.buf, c.blockSize)
		if !bytes.Equal(got, c.want) {
			t.Errorf("PKCS7Pad(%v, %v) == %v, want %v",
				c.buf, c.blockSize, got, c.want)
		}
	}
}
