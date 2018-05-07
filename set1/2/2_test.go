package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func decodeString(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TestXORBytes(t *testing.T) {
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
	var got []byte
	for _, c := range cases {
		got = make([]byte, len(c.b1))
		if XORBytes(got, c.b1, c.b2); !bytes.Equal(got, c.want) {
			t.Errorf("Xor(%v, %v) == %v, want %v",
				c.b1, c.b2, got, c.want)
		}
	}
}
