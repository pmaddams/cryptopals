// 11. An ECB/CBC detection oracle

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	weak "math/rand"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func main() {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	oracle, mode := ecbModeOracle(c)
	if detect(oracle) {
		fmt.Print("detected ECB mode...")
		if _, ok := mode.(ecbEncrypter); ok {
			fmt.Println("correct.")
		} else {
			fmt.Println("incorrect.")
		}
	} else {
		fmt.Print("detected CBC mode...")
		if _, ok := mode.(ecbEncrypter); ok {
			fmt.Println("incorrect.")
		} else {
			fmt.Println("correct.")
		}
	}
}

// ecbModeOracle takes a block cipher and returns an ECB/CBC mode oracle.
func ecbModeOracle(c cipher.Block) (func([]byte) []byte, cipher.BlockMode) {
	var mode cipher.BlockMode
	if weak.Intn(2) == 0 {
		mode = NewECBEncrypter(c)
	} else {
		mode = cipher.NewCBCEncrypter(c, RandomBytes(c.BlockSize()))
	}
	prefix := RandomBytes(RandomInRange(5, 10))
	suffix := RandomBytes(RandomInRange(5, 10))
	return func(buf []byte) []byte {
		buf = append(prefix, append(buf, suffix...)...)
		buf = PKCS7Pad(buf, mode.BlockSize())
		mode.CryptBlocks(buf, buf)
		return buf
	}, mode
}

// detect returns true if the mode oracle is using ECB mode.
func detect(oracle func([]byte) []byte) bool {
	return HasIdenticalBlocks(oracle(ecbProbe()), aes.BlockSize)
}

// ecbProbe returns a buffer that can be used to detect ECB mode.
func ecbProbe() []byte {
	return bytes.Repeat([]byte{'a'}, 3*aes.BlockSize)
}

// ecbEncrypter represents an ECB encryption block mode.
type ecbEncrypter struct{ cipher.Block }

// NewECBEncrypter returns a block mode for ECB encryption.
func NewECBEncrypter(c cipher.Block) cipher.BlockMode {
	return ecbEncrypter{c}
}

// CryptBlocks encrypts a buffer in ECB mode.
func (x ecbEncrypter) CryptBlocks(dst, src []byte) {
	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for n := x.BlockSize(); len(src) > 0; {
		x.Encrypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 0xff {
		panic("PKCS7Pad: invalid block size")
	}
	// Find the number (and value) of padding bytes.
	n := blockSize - (len(buf) % blockSize)

	return append(dup(buf), bytes.Repeat([]byte{byte(n)}, n)...)
}

// HasIdenticalBlocks returns true if any block in the buffer appears more than once.
func HasIdenticalBlocks(buf []byte, blockSize int) bool {
	m := make(map[string]bool)
	for _, block := range Subdivide(buf, blockSize) {
		s := string(block)
		if m[s] {
			return true
		}
		m[s] = true
	}
	return false
}

// Subdivide divides a buffer into blocks.
func Subdivide(buf []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for len(buf) >= blockSize {
		// Return pointers, not copies.
		blocks = append(blocks, buf[:blockSize])
		buf = buf[blockSize:]
	}
	return blocks
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// RandomInRange returns a pseudo-random non-negative integer in [lo, hi].
// The output should not be used in a security-sensitive context.
func RandomInRange(lo, hi int) int {
	if lo < 0 || lo > hi {
		panic("RandomInRange: invalid range")
	}
	return lo + weak.Intn(hi-lo+1)
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}
