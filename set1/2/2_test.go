package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestXORBytes(t *testing.T) {
	decodeString := func(s string) []byte {
		buf, _ := hex.DecodeString(s)
		return buf
	}
	cases := []struct {
		b1, b2, want []byte
	}{
		{
			decodeString("1c0111001f010100061a024b53535009181c"),
			decodeString("686974207468652062756c6c277320657965"),
			decodeString("746865206b696420646f6e277420706c6179"),
		},
		{
			[]byte{0, 0, 0, 0},
			[]byte{1, 1, 1, 1},
			[]byte{1, 1, 1, 1},
		},
		{
			[]byte{1, 0, 1, 0},
			[]byte{1, 0, 1, 0},
			[]byte{0, 0, 0, 0},
		},
	}
	for _, c := range cases {
		dst := make([]byte, len(c.b1))
		XORBytes(dst, c.b1, c.b2)
		if !bytes.Equal(dst, c.want) {
			t.Errorf("got %v, want %v", dst, c.want)
		}
	}
}
