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

func init() { weak.Seed(time.Now().UnixNano()) }

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
	for i := 0; i < 10; i++ {
		key := make([]byte, 1+weak.Intn(16))
		buf := make([]byte, 1+weak.Intn(1024))
		weak.Read(key)
		weak.Read(buf)

		// Test multiple writes.
		h := reference.New(sha1.New, key)
		h.Write(buf)
		h.Write(buf)
		h.Write(buf)
		want := h.Sum([]byte{})

		h = NewHMAC(sha1.New, key)
		h.Write(buf)
		h.Write(buf)
		h.Write(buf)
		got := h.Sum([]byte{})
		if !bytes.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
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
