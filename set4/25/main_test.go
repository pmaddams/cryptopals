package main

import (
	"bytes"
	"testing"
)

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
			t.Errorf("got %v, want %v", got, c.want)
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
