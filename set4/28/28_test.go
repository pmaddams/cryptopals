package main

import (
	"bytes"
	"crypto/sha1"
	weak "math/rand"
	"testing"
	"time"
)

func TestMAC(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	key := make([]byte, 1+weak.Intn(16))
	weak.Read(key)

	mac := NewMAC(sha1.New, key)
	for i := 0; i < 10; i++ {
		buf := make([]byte, 1+weak.Intn(1024))
		weak.Read(buf)

		mac.Reset()
		mac.Write(buf)

		sum1 := mac.Sum([]byte{})
		array := sha1.Sum(append(key, buf...))
		sum2 := array[:]
		if !bytes.Equal(sum1, sum2) {
			t.Errorf("mac == %x, sha1(key+message) == %x\n", sum1, sum2)
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
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	n := weak.Intn(1024)

	var bufs [][]byte
	for i := 0; i < 5; i++ {
		buf := RandomBytes(n)
		if len(buf) != n {
			t.Errorf("got length %v, want %v", len(buf), n)
		}
		bufs = append(bufs, buf)
		for j := 0; j < i; j++ {
			if bytes.Equal(bufs[i], bufs[j]) {
				t.Errorf("identical buffers %v and %v", bufs[i], bufs[j])
			}
		}
	}
}
