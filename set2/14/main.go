// 14. Byte-at-a-time ECB decryption (Harder)

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	weak "math/rand"
	"os"
	"sync"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

const secret = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

func main() {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	x := newECBBreaker(ecbPrefixedEncryptionOracle(c))
	if err := x.detectBlockSize(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if err := x.detectECB(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if err := x.removeOraclePrefix(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if err := x.detectSecretLength(); err != nil {
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

// ecbPrefixedEncryptionOracle takes a block cipher and returns a prefixed ECB encryption oracle.
func ecbPrefixedEncryptionOracle(c cipher.Block) func([]byte) []byte {
	prefix := RandomBytes(RandomInRange(5, 10))
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err)
	}
	mode := NewECBEncrypter(c)
	return func(buf []byte) []byte {
		res := append(prefix, append(dup(buf), decoded...)...)
		res = PKCS7Pad(res, mode.BlockSize())
		mode.CryptBlocks(res, res)
		return res
	}
}

// ecbBreaker contains state for attacking the ECB encryption oracle.
type ecbBreaker struct {
	oracle    func([]byte) []byte
	blockSize int
	secretLen int
	a         byte
}

// newECBBreaker takes an ECB encryption oracle and returns a breaker.
func newECBBreaker(oracle func([]byte) []byte) *ecbBreaker {
	return &ecbBreaker{oracle: oracle, a: 'a'}
}

// detectBlockSize detects the block size.
func (x *ecbBreaker) detectBlockSize() error {
	probe := []byte{}
	initLen := len(x.oracle(probe))
	for padLen := 0; ; padLen++ {
		if padLen > aes.BlockSize {
			return errors.New("detectBlockSize: block size greater than 16")
		}
		probe = append(probe, x.a)
		if nextLen := len(x.oracle(probe)); nextLen > initLen {
			x.blockSize = nextLen - initLen
			return nil
		}
	}
}

// detectECB returns an error if the encryption oracle is not using ECB mode.
func (x *ecbBreaker) detectECB() error {
	if x.blockSize == 0 {
		return errors.New("detectECB: invalid block size")
	}
	if !HasIdenticalBlocks(x.oracle(x.ecbProbe()), x.blockSize) {
		return errors.New("detectECB: ECB mode not detected")
	}
	return nil
}

// ecbProbe returns a buffer that can be used to detect ECB mode.
func (x *ecbBreaker) ecbProbe() []byte {
	return bytes.Repeat([]byte{x.a}, 3*x.blockSize)
}

// removeOraclePrefix replaces the oracle with a wrapper that removes the prefix.
func (x *ecbBreaker) removeOraclePrefix() error {
	if x.blockSize == 0 {
		return errors.New("removeOraclePrefix: invalid block size")
	}
	probe := []byte{}
	initBuf := x.oracle(probe)
	initLen := len(initBuf)
	prevBuf := initBuf
	for {
		if len(probe) > initLen {
			return errors.New("removeOraclePrefix: failed to remove prefix")
		}
		probe = append(probe, x.a)
		newBuf := x.oracle(probe)

		// If the last block of the initial buffer no longer changes,
		// we have gone past the end and need to step back one byte.
		if bytes.Equal(prevBuf[initLen-x.blockSize:initLen],
			newBuf[initLen-x.blockSize:initLen]) {
			probe = probe[:len(probe)-1]
			oracle := x.oracle
			x.oracle = func(buf []byte) []byte {
				return oracle(append(probe, buf...))[initLen:]
			}
			return nil
		}
		prevBuf = newBuf
	}
}

// detectSecretLength detects the secret length.
func (x *ecbBreaker) detectSecretLength() error {
	if x.blockSize == 0 {
		return errors.New("detectSecretLength: invalid block size")
	}
	probe := []byte{}
	initLen := len(x.oracle(probe))
	for padLen := 0; padLen <= x.blockSize; padLen++ {
		probe = append(probe, x.a)
		if nextLen := len(x.oracle(probe)); nextLen > initLen {
			x.secretLen = initLen - padLen
			return nil
		}
	}
	return errors.New("detectSecretLength: invalid length")
}

// breakOracle breaks the encryption oracle and returns the secret.
func (x *ecbBreaker) breakOracle() ([]byte, error) {
	if x.blockSize == 0 {
		return nil, errors.New("breakOracle: invalid block size")
	} else if x.secretLen == 0 {
		return nil, errors.New("breakOracle: invalid secret length")
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

// scanBlocks generates a sequence of blocks for decrypting the secret.
func (x *ecbBreaker) scanBlocks() [][]byte {
	// Each block enables decryption of a single byte.
	blocks := make([][]byte, x.secretLen)
	initLen := len(x.oracle([]byte{}))

	var wg sync.WaitGroup
	wg.Add(x.secretLen)
	for i := 0; i < x.secretLen; i++ {
		// Capture the value of the loop variable.
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

// PKCS7Unpad returns a buffer with PKCS#7 padding removed.
func PKCS7Unpad(buf []byte, blockSize int) ([]byte, error) {
	errInvalidPadding := errors.New("PKCS7Unpad: invalid padding")
	if len(buf) < blockSize {
		return nil, errInvalidPadding
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	n := len(buf) - int(b)
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[n:]) {
		return nil, errInvalidPadding
	}
	return dup(buf[:n]), nil
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
