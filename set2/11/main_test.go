package main

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"testing"
)

func TestRandomInRange(t *testing.T) {
	cases := []struct {
		lo, hi int
	}{
		{0, 0},
		{5, 10},
		{20, 30},
	}
	for _, c := range cases {
		for i := 0; i < 100; i++ {
			got := RandomInRange(c.lo, c.hi)
			if got < c.lo || got > c.hi {
				t.Errorf("got %v, want range [%v, %v]", got, c.lo, c.hi)
			}
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

func TestRandomEncrypter(t *testing.T) {
	modes := []cipher.BlockMode{}
	for i := 0; i < 10; i++ {
		modes = append(modes, RandomEncrypter())
	}
	_, isECB := modes[0].(ecbEncrypter)
	for i := 1; i < 10; i++ {
		if _, ok := modes[i].(ecbEncrypter); ok != isECB {
			return
		}
	}
	t.Error("identical block modes")
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
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestSubdivide(t *testing.T) {
	cases := []struct {
		buf  []byte
		n    int
		want [][]byte
	}{
		{
			[]byte{1, 2},
			3,
			nil,
		},
		{
			[]byte{1, 2, 3, 4, 5, 6},
			3,
			[][]byte{
				{1, 2, 3},
				{4, 5, 6},
			},
		},
		{
			[]byte{1, 2, 3, 4, 5, 6},
			2,
			[][]byte{
				{1, 2},
				{3, 4},
				{5, 6},
			},
		},
	}
	for _, c := range cases {
		got := Subdivide(c.buf, c.n)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestHasIdenticalBlocks(t *testing.T) {
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
		if got := HasIdenticalBlocks(c.buf, c.blockSize); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
