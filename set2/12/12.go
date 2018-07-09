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
	"sync"
)

const secret = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

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

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
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
	return dup(buf)[:len(buf)-int(b)], nil
}

// ecbEncryptionOracle returns an ECB encryption oracle.
func ecbEncryptionOracle() func([]byte) []byte {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	mode := NewECBEncrypter(c)
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err)
	}
	return func(buf []byte) []byte {
		res := append(dup(buf), decoded...)
		res = PKCS7Pad(res, mode.BlockSize())
		mode.CryptBlocks(res, res)
		return res
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
		if padLen > aes.BlockSize {
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

// Blocks divides a buffer into blocks.
func Blocks(buf []byte, n int) [][]byte {
	var bufs [][]byte
	for len(buf) >= n {
		// Return pointers, not copies.
		bufs = append(bufs, buf[:n])
		buf = buf[n:]
	}
	return bufs
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
	// Each block enables decryption of a single byte.
	blocks := make([][]byte, x.secretLen)
	initLen := len(x.oracle([]byte{}))
	var wg sync.WaitGroup

	for i := range blocks {
		wg.Add(1)
		go func(i int) {
			probe := bytes.Repeat([]byte{x.a}, initLen-1-i)
			ciphertext := x.oracle(probe)

			blocks[i] = ciphertext[initLen-x.blockSize : initLen]
			wg.Done()
		}(i)
	}
	wg.Wait()
	return blocks
}

// breakByte returns the byte that produces the given encrypted block.
func (x *ecbBreaker) breakByte(probe, block []byte) (byte, error) {
	for i := 0; i <= 0xff; i++ {
		b := byte(i)
		buf := x.oracle(append(probe, b))
		if bytes.Equal(buf[:x.blockSize], block) {
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
	probe := bytes.Repeat([]byte{x.a}, x.blockSize-1)
	for _, block := range x.scanBlocks() {
		b, err := x.breakByte(probe, block)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b)
		probe = append(probe[1:], b)
	}
	res, err := PKCS7Unpad(buf, x.blockSize)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func main() {
	x := newECBBreaker(ecbEncryptionOracle())
	if err := x.detectParameters(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if err := x.detectECB(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	buf, err := x.breakOracle()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Print(string(buf))
}
