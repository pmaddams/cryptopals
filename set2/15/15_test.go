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

func TestPKCS7Unpad(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      []byte
	}{
		{
			[]byte{0, 2, 2},
			3,
			[]byte{0},
		},
		{
			[]byte{0, 0, 1},
			3,
			[]byte{0, 0},
		},
		{
			[]byte{0, 0, 0, 3, 3, 3},
			3,
			[]byte{0, 0, 0},
		},
	}
	for _, c := range cases {
		got, _ := PKCS7Unpad(c.buf, c.blockSize)
		if !bytes.Equal(got, c.want) {
			t.Errorf("PKCS7Unpad(%v, %v) == %v, want %v",
				c.buf, c.blockSize, got, c.want)
		}
	}
}

func TestUnvis(t *testing.T) {
	cases := []struct {
		s    string
		want []byte
	}{
		{
			"\\x00\\x01\\x02",
			[]byte{0, 1, 2},
		},
		{
			"hello world",
			[]byte("hello world"),
		},
		{
			"\\xe4\\xbd\\xa0\\xe5\\xa5\\xbd",
			[]byte("你好"),
		},
	}
	for _, c := range cases {
		got, _ := Unvis(c.s)
		if !bytes.Equal(got, c.want) {
			t.Errorf("Unvis(%v) == %v, want %v",
				c.s, got, c.want)
		}
	}
}
