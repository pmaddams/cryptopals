package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	weak "math/rand"
	"time"
)

const secret = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

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

// encryptFunc returns a function that encrypts data in ECB mode
// with a random prefix and secret message added to the end.
func encryptFunc() func([]byte) []byte {
	mode := NewECBEncrypter(RandomCipher())
	prefix := RandomBytes(5, 10)
	msg, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err.Error())
	}
	return func(buf []byte) []byte {
		// Don't stomp on the original data.
		res := append(prefix, append(buf, msg...)...)
		res = PKCS7Pad(res, mode.BlockSize())
		mode.CryptBlocks(res, res)
		return res
	}
}

// detectBlockSize detects the encryption function block size.
func detectBlockSize(encrypt func([]byte) []byte) int {
	attack := []byte{}
	initLen := len(encrypt(attack))
	for {
		attack = append(attack, 'a')
		nextLen := len(encrypt(attack))
		if nextLen > initLen {
			return nextLen - initLen
		}
	}
}

// evilBuffer returns a buffer that makes it easy to detect ECB.
func evilBuffer(blockSize int) []byte {
	return bytes.Repeat([]byte{'a'}, 3*blockSize)
}

// detectMode detects whether the encryption function uses ECB or CBC mode.
func detectMode(blockSize int, encrypt func([]byte) []byte) string {
	buf := encrypt(evilBuffer(blockSize))
	// Because the evil buffer consists of the same repeated byte,
	// the encrypted blocks in the middle are identical.
	if n := aesBlockSize; bytes.Equal(buf[n:2*n], buf[2*n:3*n]) {
		return "ecb"
	}
	return "cbc"
}

// encryptWithoutPrefix takes an encryption function and returns
// a function that encrypts data in ECB mode without the prefix.
func encryptWithoutPrefix(blockSize int, encrypt func([]byte) []byte) func([]byte) []byte {
	attack := []byte{}
	initBuf := encrypt(attack)
	initLen := len(initBuf)
	prevBuf := initBuf
	for {
		attack = append(attack, 'a')
		nextBuf := encrypt(attack)

		// If the last block of the initial buffer no longer changes,
		// we have gone past the end and need to step back one byte.
		if bytes.Equal(prevBuf[initLen-blockSize:initLen],
			nextBuf[initLen-blockSize:initLen]) {
			attack = attack[:len(attack)-1]
			return func(buf []byte) []byte {
				// Now the prefix will magically disappear.
				return encrypt(append(attack, buf...))[initLen:]
			}
		}
		prevBuf = nextBuf
	}
}

func main() {
}
