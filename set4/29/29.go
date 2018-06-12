package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	_ "fmt"
	"hash"
	_ "io"
	"reflect"
	"unsafe"
)

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// BitPadding returns bit padding for the given buffer length.
func BitPadding(n, blockSize int, endian binary.ByteOrder) []byte {
	if n < 0 || blockSize < 8 {
		panic("BitPadding: invalid parameters")
	}
	var zeros int
	// Account for the first padding byte.
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

// PrefixedSHA1 returns a new SHA-1 hash using an existing checksum and buffer length.
func PrefixedSHA1(sum []byte, n int) (hash.Hash, error) {
	if len(sum) != sha1.Size {
		return nil, errors.New("PrefixedSHA1: invalid checksum")
	}
	h := sha1.New()

	var newState [5]uint32
	for i := range newState {
		newState[i] = binary.BigEndian.Uint32(sum[:4])
		sum = sum[4:]
	}
	newLen := uint64(n - (n % sha1.BlockSize) + sha1.BlockSize)

	// Circumvent the type system to modify unexported data structures.
	state := reflect.ValueOf(h).Elem().Field(0)
	state = reflect.NewAt(state.Type(), unsafe.Pointer(state.UnsafeAddr())).Elem()
	state.Set(reflect.ValueOf(newState))

	len := reflect.ValueOf(h).Elem().Field(3)
	len = reflect.NewAt(len.Type(), unsafe.Pointer(len.UnsafeAddr())).Elem()
	len.Set(reflect.ValueOf(newLen))

	return h, nil
}

// mac contains a hash and secret key.
type mac struct {
	hash.Hash
	key []byte
}

// NewMAC takes a hash and key, and returns a new MAC hash.
func NewMAC(h func() hash.Hash, key []byte) hash.Hash {
	m := mac{h(), key}
	m.Reset()
	return m
}

// Reset resets the hash.
func (m mac) Reset() {
	m.Hash.Reset()
	if _, err := m.Hash.Write(m.key); err != nil {
		panic(err)
	}
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

func main() {
}
