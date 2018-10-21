package main

import (
	"bytes"
	"crypto/sha1"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestMAC(t *testing.T) {
	key := make([]byte, 1+weak.Intn(16))
	weak.Read(key)

	mac := NewMAC(sha1.New, key)
	for i := 0; i < 10; i++ {
		buf := make([]byte, 1+weak.Intn(1024))
		weak.Read(buf)

		array := sha1.Sum(append(key, buf...))
		want := array[:]

		mac.Reset()
		mac.Write(buf)
		got := mac.Sum([]byte{})
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
