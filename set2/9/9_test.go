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

func TestFormatBytes(t *testing.T) {
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
			append([]byte("你好世界"), 31),
			"你好世界\\x1f",
		},
	}
	for _, c := range cases {
		if got := FormatBytes(c.buf); got != c.want {
			t.Errorf("FormatBytes(%v) == %v, want %v",
				c.buf, got, c.want)
		}
	}
}
