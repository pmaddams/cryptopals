package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestBitPadding(t *testing.T) {
	for i := 0; i < 10; i++ {
		n := weak.Intn(1024)
		blockSize := 8 * (1 + weak.Intn(16))
		var endian binary.ByteOrder
		if weak.Intn(2) == 0 {
			endian = binary.LittleEndian
		} else {
			endian = binary.BigEndian
		}
		pad := BitPadding(n, blockSize, endian)
		fail := func(s string) {
			t.Fatalf("BitPadding(%v, %v, %v) == %v, %s",
				n, blockSize, endian, pad, s)
		}
		if len(pad) < 8 {
			fail("padding too short")
		}
		if (n+len(pad))%blockSize != 0 {
			fail("padded length not a multiple of the block size")
		}
		if pad[0] != 0x80 {
			fail("invalid first padding byte")
		}
		tmp := make([]byte, 8)
		endian.PutUint64(tmp, uint64(n)<<3)
		if !bytes.Equal(tmp, pad[len(pad)-8:]) {
			fail("incorrect bit count")
		}
	}
}

func TestPrefixedSHA1(t *testing.T) {
	for i := 0; i < 10; i++ {
		h := sha1.New()
		b1 := make([]byte, weak.Intn(1024))
		weak.Read(b1)
		h.Write(b1)
		sum := h.Sum([]byte{})

		pad := BitPadding(len(b1), sha1.BlockSize, binary.BigEndian)

		h.Reset()
		b2 := make([]byte, weak.Intn(1024))
		weak.Read(b2)
		h.Write(append(b1, append(pad, b2...)...))
		want := h.Sum([]byte{})

		h, err := PrefixedSHA1(sum, len(b1))
		if err != nil {
			t.Fatal(err)
		}
		h.Write(b2)
		got := h.Sum([]byte{})
		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	}
}

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

func TestRandomInRange(t *testing.T) {
	cases := []struct {
		lo, hi int
	}{
		{0, 0},
		{5, 10},
		{20, 30},
	}
	for _, c := range cases {
		for i := 0; i < 100; i++ {
			got := RandomInRange(c.lo, c.hi)
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
