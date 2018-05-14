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

// NewECBEncrypter returns a cipher.BlockMode that encrypts in ECB mode.
func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return ecbEncrypter{block}
}

// BlockSize returns the block size of the cipher.
func (mode ecbEncrypter) BlockSize() int {
	return mode.b.BlockSize()
}

// CryptBlocks implements ECB encryption for multiple blocks.
func (mode ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%mode.BlockSize() != 0 {
		panic("CryptBlocks: input not full blocks")
	}
	for n := mode.BlockSize(); len(src) > 0; {
		mode.b.Encrypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

// evilBuffer returns a buffer that makes it easy to detect ECB.
func evilBuffer() []byte {
	return bytes.Repeat([]byte{'a'}, 3*aesBlockSize)
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

// AddRandomBytes returns a buffer with random bytes added to both ends,
// such that the overall length is a multiple of the AES block size.
func AddRandomBytes(buf []byte) []byte {
	prefix, suffix := RandomBytes(5, 10), RandomBytes(5, 10)
	buf = append(append(prefix, buf...), suffix...)
	// Extend the buffer to a multiple of the block size.
	if rem := len(buf) % aesBlockSize; rem != 0 {
		n := aesBlockSize - rem
		buf = append(buf, RandomBytes(n, n)...)
	}
	return buf
}

// detectMode takes either an ECB or CBC block mode and detects which one it is.
func detectMode(mode cipher.BlockMode) string {
	buf := AddRandomBytes(evilBuffer())
	mode.CryptBlocks(buf, buf)
	// Because the evil buffer consists of the same repeated byte,
	// the encrypted blocks in the middle are identical.
	if n := aesBlockSize; bytes.Equal(buf[n:2*n], buf[2*n:3*n]) {
		return "ecb"
	}
	return "cbc"
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

func main() {
	switch mode := RandomEncrypter(); detectMode(mode) {
	case "ecb":
		fmt.Print("Detected ECB mode...")
		if _, ok := mode.(ecbEncrypter); ok {
			fmt.Println("correct.")
		} else {
			fmt.Println("incorrect.")
		}
	case "cbc":
		fmt.Print("Detected CBC mode...")
		if _, ok := mode.(ecbEncrypter); ok {
			fmt.Println("incorrect.")
		} else {
			fmt.Println("correct.")
		}
	}
}
