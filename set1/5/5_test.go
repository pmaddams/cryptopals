package main

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func TestXORCipher(t *testing.T) {
	cases := []struct {
		stream    cipher.Stream
		src, want []byte
	}{
		{
			NewXORCipher([]byte{1, 2}),
			[]byte{1, 2, 3, 4, 5, 6},
			[]byte{0, 0, 2, 6, 4, 4},
		},
		{
			NewXORCipher([]byte{1, 2, 3}),
			[]byte{1, 2, 3, 4, 5, 6},
			[]byte{0, 0, 0, 5, 7, 5},
		},
		{
			NewXORCipher([]byte{1, 2, 3, 4}),
			[]byte{1, 2, 3, 4, 5, 6},
			[]byte{0, 0, 0, 0, 4, 4},
		},
	}
	for _, c := range cases {
		dst := make([]byte, len(c.src))
		if c.stream.XORKeyStream(dst, c.src); !bytes.Equal(dst, c.want) {
			t.Errorf("(%v).XORKeyStream(%v, %v), want %v",
				c.stream, dst, c.src, c.want)
		}
	}
}
