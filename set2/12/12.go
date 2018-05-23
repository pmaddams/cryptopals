package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
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
		panic(fmt.Sprintf("RandomCipher: %s", err.Error()))
	}
	block, _ := aes.NewCipher(key)
	return block
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

// PKCS7Unpad returns a buffer with PKCS#7 padding removed.
func PKCS7Unpad(buf []byte, blockSize int) ([]byte, error) {
	if len(buf) < blockSize {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	return buf[:len(buf)-int(b)], nil
}

// ecbEncryptionOracle returns an ECB encryption oracle function.
func ecbEncryptionOracle() func([]byte) []byte {
	mode := NewECBEncrypter(RandomCipher())
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(fmt.Sprintf("ecbEncryptionOracle: %s", err.Error()))
	}
	return func(buf []byte) []byte {
		buf = append(buf, decoded...)
		buf = PKCS7Pad(buf, mode.BlockSize())
		mode.CryptBlocks(buf, buf)
		return buf
	}
}

// ecbBreaker contains data necessary to attack the ECB encryption oracle.
type ecbBreaker struct {
	oracle    func([]byte) []byte
	a         byte
	blockSize int
	secretLen int
}

// newECBBreaker takes an ECB encryption oracle and returns a breaker.
func newECBBreaker(oracle func([]byte) []byte) *ecbBreaker {
	return &ecbBreaker{oracle: oracle, a: 'a'}
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
func (x *ecbBreaker) ecbProbe() []byte {
	return bytes.Repeat([]byte{x.a}, 3*x.blockSize)
}

// detectECB returns an error if the encryption oracle is not using ECB mode.
func (x *ecbBreaker) detectECB() error {
	if x.blockSize == 0 {
		return errors.New("detectECB: invalid block size")
	}
	if !IdenticalBlocks(x.oracle(x.ecbProbe()), x.blockSize) {
		return errors.New("detectECB: ECB mode not detected")
	}
	return nil
}

// scanBlocks generates a sequence of blocks for decrypting the secret.
func (x *ecbBreaker) scanBlocks() [][]byte {
	initLen := len(x.oracle([]byte{}))
	probe := bytes.Repeat([]byte{x.a}, initLen-1)

	// Each block enables decryption of a single byte.
	blocks := make([][]byte, x.secretLen)
	for i := range blocks {
		buf := x.oracle(probe)
		blocks[i] = buf[initLen-x.blockSize : initLen]
		// Shift the secret forward one byte.
		probe = probe[:len(probe)-1]
	}
	return blocks
}

// breakByte returns the byte that produces the given encrypted block.
func (x *ecbBreaker) breakByte(probe, block []byte) (byte, error) {
	for i := 0; i < 256; i++ {
		b := byte(i)
		probe[x.blockSize-1] = b
		buf := x.oracle(probe)
		if bytes.Equal(buf[:x.blockSize], block) {
			// Shift the probe forward one byte.
			copy(probe, probe[1:])
			return b, nil
		}
	}
	return 0, errors.New("breakByte: invalid block")
}

// breakOracle breaks the encryption oracle and returns the secret.
func (x *ecbBreaker) breakOracle() ([]byte, error) {
	if x.blockSize == 0 {
		return nil, errors.New("scanBlocks: invalid block size")
	} else if x.secretLen == 0 {
		return nil, errors.New("scanBlocks: invalid secret length")
	}
	var buf []byte
	probe := bytes.Repeat([]byte{x.a}, x.blockSize)
	for _, block := range x.scanBlocks() {
		b, err := x.breakByte(probe, block)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b)
	}
	res, err := PKCS7Unpad(buf, x.blockSize)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func main() {
	x := newECBBreaker(ecbEncryptionOracle())
	var err error
	if err = x.detectParameters(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if err = x.detectECB(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	var buf []byte
	if buf, err = x.breakOracle(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Print(string(buf))
}
