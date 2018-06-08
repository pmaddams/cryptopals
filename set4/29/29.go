package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"unsafe"
)

// PrefixSHA1 returns a new SHA-1 hash using register values from an existing checksum.
func PrefixSHA1(sum []byte) (hash.Hash, error) {
	if len(sum) != sha1.Size {
		return nil, errors.New("PrefixSHA1: invalid checksum")
	}
	src := [5]uint32{
		binary.BigEndian.Uint32(sum[:4]),
		binary.BigEndian.Uint32(sum[4:8]),
		binary.BigEndian.Uint32(sum[8:12]),
		binary.BigEndian.Uint32(sum[12:16]),
		binary.BigEndian.Uint32(sum[16:20]),
	}
	h := sha1.New()

	// Circumvent the type system to access an unexported field.
	dst := reflect.ValueOf(h).Elem().Field(0)
	dst = reflect.NewAt(dst.Type(), unsafe.Pointer(dst.UnsafeAddr())).Elem()
	dst.Set(reflect.ValueOf(src))

	return h, nil
}

// HashPadding returns the hash padding for the given buffer.
func HashPadding(buf []byte, blockSize int) ([]byte, error) {
	if blockSize < 8 {
		return nil, errors.New("HashPadding: invalid block size")
	}
	var n int
	// Account for the minimum padding byte.
	if rem := (len(buf) + 1) % blockSize; rem > blockSize-8 {
		n = 2*blockSize - rem
	} else {
		n = blockSize - rem
	}
	res := append([]byte{1}, bytes.Repeat([]byte{0}, n)...)
	binary.BigEndian.PutUint64(res[len(res)-8:], uint64(len(buf)))

	return res, nil
}

func main() {
	h, err := PrefixSHA1(bytes.Repeat([]byte{0}, 20))
	if err != nil {
		panic(err)
	}
	fmt.Println(h)
}
