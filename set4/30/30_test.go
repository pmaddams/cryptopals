package main

import (
	"bytes"
	"encoding/binary"
	weak "math/rand"
	"testing"
	"time"

	"golang.org/x/crypto/md4"
)

func TestBitPadding(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	for i := 0; i < 10; i++ {
		n := weak.Intn(1024)
		blockSize := 8 * (1 + weak.Intn(16))
		var endian binary.ByteOrder
		switch weak.Intn(2) {
		case 0:
			endian = binary.LittleEndian
		default:
			endian = binary.BigEndian
		}
		pad := BitPadding(n, blockSize, endian)
		fail := func(s string) {
			t.Errorf("BitPadding(%v, %v, %v) == %v, %s",
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

func TestPrefixedMD4(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	for i := 0; i < 10; i++ {
		h := md4.New()
		buf1 := make([]byte, weak.Intn(1024))
		weak.Read(buf1)
		h.Write(buf1)
		sum := h.Sum([]byte{})

		pad := BitPadding(len(buf1), md4.BlockSize, binary.LittleEndian)

		h.Reset()
		buf2 := make([]byte, weak.Intn(1024))
		weak.Read(buf2)
		h.Write(append(buf1, append(pad, buf2...)...))
		want := h.Sum([]byte{})

		h, err := PrefixedMD4(sum, len(buf1))
		if err != nil {
			t.Fatal(err)
		}
		h.Write(buf2)
		got := h.Sum([]byte{})
		if !bytes.Equal(got, want) {
			t.Errorf("PrefixedMD4(%x, %v) == %x, want %x",
				sum, len(buf1), got, want)
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
