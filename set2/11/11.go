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

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// ecbEncrypter embeds cipher.Block, hiding its methods.
type ecbEncrypter struct{ b cipher.Block }

// NewECBEncrypter returns a block mode for ECB encryption.
func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return ecbEncrypter{block}
}

// BlockSize returns the block size of the cipher.
func (mode ecbEncrypter) BlockSize() int {
	return mode.b.BlockSize()
}

// CryptBlocks encrypts a buffer in ECB mode.
func (mode ecbEncrypter) CryptBlocks(dst, src []byte) {
	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for n := mode.BlockSize(); len(src) > 0; {
		mode.b.Encrypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

// RandomCipher returns an AES cipher with a random key.
func RandomCipher() cipher.Block {
	key := make([]byte, aesBlockSize)
	if _, err := rand.Read(key); err != nil {
		panic(err.Error())
	}
	block, _ := aes.NewCipher(key)
	return block
}

// RandomEncrypter returns either ECB or CBC encryption mode with a random key.
func RandomEncrypter() cipher.BlockMode {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	switch weak.Intn(2) {
	case 0:
		return NewECBEncrypter(RandomCipher())
	default:
		iv := make([]byte, aesBlockSize)
		if _, err := rand.Read(iv); err != nil {
			panic(err.Error())
		}
		return cipher.NewCBCEncrypter(RandomCipher(), iv)
	}
}

// RandomBytes returns a random buffer with length in [min, max].
func RandomBytes(min, max int) []byte {
	if min < 0 || min > max {
		panic("RandomBytes: invalid range")
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	res := make([]byte, min+weak.Intn(max-min+1))
	if _, err := rand.Read(res); err != nil {
		panic(err.Error())
	}
	return res
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	var n int

	// If the buffer length is a multiple of the block size,
	// add a number of padding bytes equal to the block size.
	if rem := len(buf) % blockSize; rem == 0 {
		n = blockSize
	} else {
		n = blockSize - rem
	}
	for i := 0; i < n; i++ {
		buf = append(buf, byte(n))
	}
	return buf
}

// ecbModeOracle returns an ECB/CBC mode oracle function.
func ecbModeOracle(mode cipher.BlockMode) func([]byte) []byte {
	prefix, suffix := RandomBytes(5, 10), RandomBytes(5, 10)
	return func(buf []byte) []byte {
		buf = append(prefix, append(buf, suffix...)...)
		buf = PKCS7Pad(buf, mode.BlockSize())
		mode.CryptBlocks(buf, buf)
		return buf
	}
}

// IdenticalBlocks returns true if any block in the buffer appears more than once.
func IdenticalBlocks(buf []byte, blockSize int) bool {
	for ; len(buf) >= 2*blockSize; buf = buf[blockSize:] {
		for p := buf[blockSize:]; len(p) >= blockSize; p = p[blockSize:] {
			if bytes.Equal(buf[:blockSize], p[:blockSize]) {
				return true
			}
		}
	}
	return false
}

// ecbProbe returns a buffer that can be used to detect ECB mode.
func ecbProbe() []byte {
	return bytes.Repeat([]byte{'a'}, 3*aesBlockSize)
}

// detectECB returns true if the mode oracle is using ECB mode.
func detectECB(oracle func([]byte) []byte) bool {
	return IdenticalBlocks(oracle(ecbProbe()), aesBlockSize)
}

func main() {
	mode := RandomEncrypter()
	if detectECB(ecbModeOracle(mode)) {
		fmt.Print("Detected ECB mode...")
		if _, ok := mode.(ecbEncrypter); ok {
			fmt.Println("correct.")
		} else {
			fmt.Println("incorrect.")
		}
	} else {
		fmt.Print("Detected CBC mode...")
		if _, ok := mode.(ecbEncrypter); ok {
			fmt.Println("incorrect.")
		} else {
			fmt.Println("correct.")
		}
	}
}
