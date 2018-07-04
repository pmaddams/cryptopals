package main

import (
	"bytes"
	reference "crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	weak "math/rand"
	"testing"
	"time"
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

func TestHMAC(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	for i := 0; i < 10; i++ {
		key := make([]byte, 1+weak.Intn(16))
		weak.Read(key)

		h1 := NewHMAC(sha1.New, key)
		h2 := reference.New(sha1.New, key)

		buf := make([]byte, 1+weak.Intn(1024))
		weak.Read(buf)

		// Test multiple consecutive writes.
		h1.Write(buf)
		h1.Write(buf)
		h1.Write(buf)

		h2.Write(buf)
		h2.Write(buf)
		h2.Write(buf)

		sum1, sum2 := h1.Sum([]byte{}), h2.Sum([]byte{})
		if !bytes.Equal(sum1, sum2) {
			t.Errorf("hmac == %x, reference == %x\n", sum1, sum2)
		}
	}
}

func TestRandomRange(t *testing.T) {
	cases := []struct {
		lo, hi int
	}{
		{0, 0},
		{5, 10},
		{20, 30},
	}
	for _, c := range cases {
		for i := 0; i < 100; i++ {
			got := RandomRange(c.lo, c.hi)
			if got < c.lo || got > c.hi {
				t.Errorf("RandomRange(%v, %v) == %v, value out of range",
					c.lo, c.hi, got)
			}
		}
	}
}

func TestRandomBytes(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	n := weak.Intn(1024)

	var cases [][]byte
	for i := 0; i < 5; i++ {
		buf := RandomBytes(n)
		if len(buf) != n {
			t.Errorf("RandomBytes(%v) == %v, length %v",
				n, buf, len(buf))
		}
		cases = append(cases, buf)
		for j := 0; j < i; j++ {
			if bytes.Equal(cases[i], cases[j]) {
				t.Errorf("RandomBytes created identical buffers %v and %v",
					cases[i], cases[j])
			}
		}
	}
}
