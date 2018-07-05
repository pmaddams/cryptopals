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

// ecbEncrypter represents an ECB encryption block mode.
type ecbEncrypter struct{ c cipher.Block }

// NewECBEncrypter returns a block mode for ECB encryption.
func NewECBEncrypter(c cipher.Block) cipher.BlockMode {
	return ecbEncrypter{c}
}

// BlockSize returns the cipher block size.
func (mode ecbEncrypter) BlockSize() int {
	return mode.c.BlockSize()
}

// CryptBlocks encrypts a buffer in ECB mode.
func (mode ecbEncrypter) CryptBlocks(dst, src []byte) {
	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for n := mode.BlockSize(); len(src) > 0; {
		mode.c.Encrypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

// RandomRange returns a pseudo-random non-negative integer in [lo, hi].
// The output should not be used in a security-sensitive context.
func RandomRange(lo, hi int) int {
	if lo < 0 || lo > hi {
		panic("RandomRange: invalid range")
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	return lo + weak.Intn(hi-lo+1)
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

// RandomEncrypter returns either ECB or CBC encryption mode with a random key.
func RandomEncrypter() cipher.BlockMode {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	switch RandomRange(0, 1) {
	case 0:
		return NewECBEncrypter(c)
	default:
		return cipher.NewCBCEncrypter(c, RandomBytes(c.BlockSize()))
	}
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
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

// ecbModeOracle returns an ECB/CBC mode oracle.
func ecbModeOracle(mode cipher.BlockMode) func([]byte) []byte {
	prefix := RandomBytes(RandomRange(5, 10))
	suffix := RandomBytes(RandomRange(5, 10))
	return func(buf []byte) []byte {
		buf = append(prefix, append(buf, suffix...)...)
		buf = PKCS7Pad(buf, mode.BlockSize())
		mode.CryptBlocks(buf, buf)
		return buf
	}
}

// Blocks divides a buffer into blocks.
func Blocks(buf []byte, n int) [][]byte {
	var res [][]byte
	for len(buf) >= n {
		// Return pointers, not copies.
		res = append(res, buf[:n])
		buf = buf[n:]
	}
	return res
}

// IdenticalBlocks returns true if any block in the buffer appears more than once.
func IdenticalBlocks(buf []byte, blockSize int) bool {
	m := make(map[string]bool)
	for _, block := range Blocks(buf, blockSize) {
		s := string(block)
		if m[s] {
			return true
		}
		m[s] = true
	}
	return false
}

// ecbProbe returns a buffer that can be used to detect ECB mode.
func ecbProbe() []byte {
	return bytes.Repeat([]byte{'a'}, 3*aes.BlockSize)
}

// detectECB returns true if the mode oracle is using ECB mode.
func detectECB(oracle func([]byte) []byte) bool {
	return IdenticalBlocks(oracle(ecbProbe()), aes.BlockSize)
}

func main() {
	mode := RandomEncrypter()
	if detectECB(ecbModeOracle(mode)) {
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
