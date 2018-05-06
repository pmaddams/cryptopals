package main

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestHexToB64(t *testing.T) {
	cases := []struct {
		s, want string
	}{
		{
			"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
		{
			hex.EncodeToString([]byte("hello world")),
			base64.StdEncoding.EncodeToString([]byte("hello world")),
		},
		{
			hex.EncodeToString([]byte("你好世界")),
			base64.StdEncoding.EncodeToString([]byte("你好世界")),
		},
	}
	for _, c := range cases {
		if got, _ := HexToB64(c.s); got != c.want {
			t.Errorf("HexToB64(%v) == %v, want %v",
				c.s, got, c.want)
		}
	}
}
