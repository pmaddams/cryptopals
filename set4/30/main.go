// 30. Break an MD4 keyed MAC using length extension

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	weak "math/rand"
	"os"
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/crypto/md4"
)

func init() { weak.Seed(time.Now().UnixNano()) }

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
	buf := append([]byte{0x80}, bytes.Repeat([]byte{0}, zeros)...)

	// Write the bit count as an unsigned 64-bit integer.
	endian.PutUint64(buf[len(buf)-8:], uint64(n)<<3)

	return buf
}

// setUnexported sets a possibly unexported value.
func setUnexported(v1, v2 reflect.Value) {
	reflect.NewAt(v1.Type(), unsafe.Pointer(v1.UnsafeAddr())).Elem().Set(v2)
}

// PrefixedMD4 returns a new MD4 hash using an existing checksum and buffer length.
func PrefixedMD4(sum []byte, n int) (hash.Hash, error) {
	if len(sum) != md4.Size {
		return nil, errors.New("PrefixedMD4: invalid checksum")
	}
	h := md4.New()

	var state [4]uint32
	for i := range state {
		state[i] = binary.LittleEndian.Uint32(sum[:4])
		sum = sum[4:]
	}
	pad := BitPadding(n, md4.BlockSize, binary.LittleEndian)
	written := uint64(n + len(pad))

	setUnexported(reflect.ValueOf(h).Elem().Field(0), reflect.ValueOf(state))
	setUnexported(reflect.ValueOf(h).Elem().Field(3), reflect.ValueOf(written))

	return h, nil
}

// mac represents a hash for a secret-prefix message authentication code.
type mac struct {
	hash.Hash
	key []byte
}

// NewMAC takes a hash and key, and returns a new MAC hash.
func NewMAC(fn func() hash.Hash, key []byte) hash.Hash {
	x := mac{fn(), key}
	x.Reset()
	return x
}

// Reset resets the hash.
func (x mac) Reset() {
	x.Hash.Reset()
	if _, err := x.Hash.Write(x.key); err != nil {
		panic(err)
	}
}

// RandomRange returns a pseudo-random non-negative integer in [lo, hi].
// The output should not be used in a security-sensitive context.
func RandomRange(lo, hi int) int {
	if lo < 0 || lo > hi {
		panic("RandomRange: invalid range")
	}
	return lo + weak.Intn(hi-lo+1)
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func main() {
	const (
		prefix = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
		suffix = ";admin=true"
	)
	key := RandomBytes(RandomRange(8, 64))
	mac := NewMAC(md4.New, key)

	io.WriteString(mac, prefix)
	sum := mac.Sum([]byte{})

	// Guess the key length.
	for n := 8; n <= 64; n++ {
		h, err := PrefixedMD4(sum, n+len(prefix))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		io.WriteString(h, suffix)
		guess := h.Sum([]byte{})

		pad := BitPadding(n+len(prefix), md4.BlockSize, binary.LittleEndian)

		mac.Reset()
		fmt.Fprintf(mac, "%s%s%s", prefix, pad, suffix)
		check := mac.Sum([]byte{})

		if bytes.Equal(guess, check) {
			fmt.Printf("guess: %x\ncheck: %x\n", guess, check)
			return
		}
	}
}
