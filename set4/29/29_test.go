package main

import (
	"bytes"
	"encoding/binary"
	weak "math/rand"
	"testing"
	"time"
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
