package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"reflect"
	"unsafe"
)

// PrefixedSHA1 returns a new SHA-1 hash using an existing checksum and buffer length.
func PrefixedSHA1(sum []byte, n int) (hash.Hash, error) {
	if len(sum) != sha1.Size {
		return nil, errors.New("PrefixedSHA1: invalid checksum")
	}
	h := sha1.New()
	newstate := [5]uint32{
		binary.BigEndian.Uint32(sum[:4]),
		binary.BigEndian.Uint32(sum[4:8]),
		binary.BigEndian.Uint32(sum[8:12]),
		binary.BigEndian.Uint32(sum[12:16]),
		binary.BigEndian.Uint32(sum[16:20]),
	}
	newlen := uint64(n - (n % sha1.BlockSize) + sha1.BlockSize)

	// Circumvent the type system to access unexported data structures.
	state := reflect.ValueOf(h).Elem().Field(0)
	state = reflect.NewAt(state.Type(), unsafe.Pointer(state.UnsafeAddr())).Elem()
	state.Set(reflect.ValueOf(newstate))

	len := reflect.ValueOf(h).Elem().Field(3)
	len = reflect.NewAt(len.Type(), unsafe.Pointer(len.UnsafeAddr())).Elem()
	len.Set(reflect.ValueOf(newlen))

	return h, nil
}

// BitPadding returns bit padding for the given buffer length.
func BitPadding(n, blockSize int, endian binary.ByteOrder) []byte {
	if n < 0 || blockSize < 8 {
		panic("BitPadding: invalid parameters")
	}
	var zeros int
	// Account for the padding "1" byte.
	if rem := (n + 1) % blockSize; rem > blockSize-8 {
		zeros = 2*blockSize - rem
	} else {
		zeros = blockSize - rem
	}
	res := append([]byte{0x80}, bytes.Repeat([]byte{0}, zeros)...)

	// Write the bit count as an unsigned 64-bit integer.
	endian.PutUint64(res[len(res)-8:], uint64(n)<<3)

	return res
}

func main() {
	h1 := sha1.New()
	io.WriteString(h1, "hello")
	sum1 := h1.Sum([]byte{})

	h2, err := PrefixedSHA1(sum1, len("hello"))
	if err != nil {
		panic(err)
	}
	io.WriteString(h2, "world")
	sum2 := h2.Sum([]byte{})
	fmt.Printf("%x\n", sum2)

	pad := BitPadding(len("hello"), sha1.BlockSize, binary.BigEndian)
	buf := append([]byte("hello"), append(pad, []byte("world")...)...)
	h3 := sha1.New()
	h3.Write(buf)
	sum3 := h3.Sum([]byte{})
	fmt.Printf("%x\n", sum3)
}
