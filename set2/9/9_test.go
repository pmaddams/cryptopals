package main

import (
	"bytes"
	"testing"
)

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

func TestVis(t *testing.T) {
	cases := []struct {
		buf  []byte
		want string
	}{
		{
			[]byte{0, 1, 2},
			"\\x00\\x01\\x02",
		},
		{
			[]byte("hello world"),
			"hello world",
		},
		{
			[]byte("你好"),
			"\\xe4\\xbd\\xa0\\xe5\\xa5\\xbd",
		},
	}
	for _, c := range cases {
		if got := Vis(c.buf); got != c.want {
			t.Errorf("Vis(%v) == %v, want %v",
				c.buf, got, c.want)
		}
	}
}
