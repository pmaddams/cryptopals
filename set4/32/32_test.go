package main

import (
	"bytes"
	weak "math/rand"
	"testing"
	"time"
)

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
