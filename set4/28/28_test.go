package main

import (
	"bytes"
	"crypto/sha1"
	weak "math/rand"
	"testing"
	"time"
)

func TestSum(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	n := 1 + weak.Intn(16)

	key := RandomBytes(n)
	h := NewMAC(sha1.New, key)

	for i := 0; i < 10; i++ {
		n := 1 + weak.Intn(1024)
		buf := RandomBytes(n)

		h.Reset()
		h.Write(buf)

		mac := h.Sum([]byte{})
		array := sha1.Sum(append(key, buf...))
		sum := array[:]
		if !bytes.Equal(mac, sum) {
			t.Errorf("mac == %x, sha1(key+message) == %x\n", mac, sum)
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
