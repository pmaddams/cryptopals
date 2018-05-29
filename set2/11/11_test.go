package main

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func TestRandomRange(t *testing.T) {
	cases := []struct {
		lo, hi int
	}{
		{0, 0},
		{5, 10},
		{20, 30},
	}
	for _, c := range cases {
		for i := 0; i < 10; i++ {
			got := RandomRange(c.lo, c.hi)
			if got < c.lo || got > c.hi {
				t.Errorf("RandomRange(%v, %v) == %v, value out of range",
					c.lo, c.hi, got)
			}
		}
	}
}

func TestRandomBytes(t *testing.T) {
	const length = 10
	cases := [][]byte{}
	for i := 0; i < 5; i++ {
		cases = append(cases, RandomBytes(length))
		for j := 0; j < i; j++ {
			if bytes.Equal(cases[i], cases[j]) {
				t.Errorf("RandomBytes created identical buffers %v and %v",
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

func TestIdenticalBlocks(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      bool
	}{
		{
			[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3},
			3,
			true,
		},
		{
			[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 4, 5, 6},
			3,
			true,
		},
		{
			[]byte{1, 2, 3, 1, 3, 2, 3, 1, 3, 2, 3, 1},
			3,
			false,
		},
	}
	for _, c := range cases {
		if got := IdenticalBlocks(c.buf, c.blockSize); got != c.want {
			t.Errorf("IdenticalBlocks(%v, %v) == %v, want %v",
				c.buf, c.blockSize, got, c.want)
		}
	}
}
