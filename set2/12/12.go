package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
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

// ecbEncryptionOracle returns an ECB encryption oracle function.
func ecbEncryptionOracle() func([]byte) []byte {
	mode := NewECBEncrypter(RandomCipher())
	prefix := RandomBytes(5, 10)
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err.Error())
	}
	return func(buf []byte) []byte {
		// Don't stomp on the original data.
		res := append(prefix, append(buf, decoded...)...)
		res = PKCS7Pad(res, mode.BlockSize())
		mode.CryptBlocks(res, res)
		return res
	}
}

// ecbBreaker contains the data necessary to analyze an ECB encryption oracle.
type ecbBreaker struct {
	oracle func([]byte) []byte
	a byte
	blockSize int
	secretLen int
}

// detectParameters detects the block size and secret length.
func (x *ecbBreaker) detectParameters() error {
	probe := []byte{}
	initLen := len(x.oracle(probe))
	for padLen := 0; ; padLen++ {
		if padLen > aesBlockSize {
			return errors.New("detectParameters: block size greater than 16")
		}
		probe = append(probe, x.a)
		if nextLen := len(x.oracle(probe)); nextLen > initLen {
			x.blockSize = nextLen - initLen
			x.secretLen = initLen - padLen
			return nil
		}
	}
}

// ecbProbe returns a buffer that can be used to detect ECB mode.
func (x *ecbBreaker) ecbProbe() []byte {
	return bytes.Repeat([]byte{x.a}, 3*x.blockSize)
}

// detectECB returns an error if the encryption oracle is not using ECB mode.
func (x *ecbBreaker) detectECB() error {
	buf := x.oracle(x.ecbProbe())
	// Because the probe consists of the same repeated byte,
	// the encrypted blocks in the middle are identical.
	if n := x.blockSize; bytes.Equal(buf[n:2*n], buf[2*n:3*n]) {
		return nil
	}
	return errors.New("detectECB: ECB mode not detected")
}

// NewECBBreaker takes an ECB encryption oracle and returns a breaker.
func NewECBBreaker(oracle func([]byte) []byte) (*ecbBreaker, error) {
	x := &ecbBreaker{oracle: oracle, a: 'a'}
	if err := x.detectParameters(); err != nil {
		return nil, err
	}
	if err := x.detectECB(); err != nil {
		return nil, err
	}
	return x, nil
}

func main() {
}
