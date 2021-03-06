// 17. The CBC padding oracle

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	weak "math/rand"
	"os"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func main() {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	iv, ciphertext, err := cbcRandomLine("17.txt", c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	oracle := cbcPaddingOracle(c)
	x := newCBCBreaker(oracle, iv, ciphertext)

	buf, err := x.breakOracle()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(string(buf))
}

// cbcRandomLine returns an encrypted line and its IV from a file containing base64-encoded strings.
func cbcRandomLine(file string, c cipher.Block) ([]byte, []byte, error) {
	buf, err := randomLine(file)
	if err != nil {
		return nil, nil, err
	}
	iv := RandomBytes(c.BlockSize())
	mode := cipher.NewCBCEncrypter(c, iv)
	buf = PKCS7Pad(buf, mode.BlockSize())
	mode.CryptBlocks(buf, buf)
	return iv, buf, nil
}

// randomLine returns a random line from a file containing base64-encoded strings.
func randomLine(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	input := bufio.NewScanner(f)
	var lines []string
	for input.Scan() {
		lines = append(lines, input.Text())
	}
	if err := input.Err(); err != nil {
		return nil, err
	}
	s := lines[weak.Intn(len(lines))]

	return base64.StdEncoding.DecodeString(s)
}

// cbcPaddingOracle returns a CBC padding oracle.
func cbcPaddingOracle(c cipher.Block) func([]byte, []byte) bool {
	return func(iv, buf []byte) bool {
		return cbcValidPadding(iv, buf, c)
	}
}

// cbcValidPadding returns true if a decrypted buffer has valid PKCS#7 padding.
func cbcValidPadding(iv, buf []byte, c cipher.Block) bool {
	mode := cipher.NewCBCDecrypter(c, iv)
	tmp := make([]byte, len(buf))
	mode.CryptBlocks(tmp, buf)
	return ValidPadding(tmp, mode.BlockSize())
}

// ValidPadding returns true if a buffer has valid PKCS#7 padding.
func ValidPadding(buf []byte, blockSize int) bool {
	if _, err := PKCS7Unpad(buf, blockSize); err != nil {
		return false
	}
	return true
}

// cbcBreaker contains state for attacking the CBC padding oracle.
type cbcBreaker struct {
	oracle     func([]byte, []byte) bool
	iv         []byte
	ciphertext []byte
	blockSize  int
}

// newCBCBreaker takes a CBC padding oracle, IV, and ciphertext, and returns a breaker.
func newCBCBreaker(oracle func([]byte, []byte) bool, iv, ciphertext []byte) *cbcBreaker {
	return &cbcBreaker{
		oracle:     oracle,
		iv:         iv,
		ciphertext: ciphertext,
		blockSize:  len(iv),
	}
}

// breakOracle breaks the padding oracle and returns the plaintext.
func (x *cbcBreaker) breakOracle() ([]byte, error) {
	blocks := Subdivide(x.ciphertext, x.blockSize)
	buf, err := x.breakBlock(x.iv, blocks[0])
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(blocks); i++ {
		block, err := x.breakBlock(blocks[i-1], blocks[i])
		if err != nil {
			return nil, err
		}
		buf = append(buf, block...)
	}
	res, err := PKCS7Unpad(buf, x.blockSize)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// breakBlock takes an IV and block of ciphertext, and returns the plaintext.
func (x *cbcBreaker) breakBlock(iv, buf []byte) ([]byte, error) {
	res, tmp := make([]byte, x.blockSize), make([]byte, x.blockSize)

	// Iterate over the range of padding values.
	for v := 1; v <= x.blockSize; v++ {
		// XOR the IV by the known plaintext bytes.
		XORBytes(tmp, iv, res)

		// XOR the IV by the desired padding bytes.
		XORBytes(tmp[x.blockSize-v:], tmp[x.blockSize-v:],
			bytes.Repeat([]byte{byte(v)}, v))

		b, err := x.breakPaddingByte(tmp, buf, v)
		if err != nil {
			return nil, err
		}
		res[x.blockSize-v] = b
	}
	return res, nil
}

// breakPaddingByte returns the plaintext byte for the given padding value.
func (x *cbcBreaker) breakPaddingByte(tmp, buf []byte, v int) (byte, error) {
	b := tmp[x.blockSize-v]

	// Iterate backwards to avoid restoring an original padding byte.
	for i := 0xff; i >= 0; i-- {
		tmp[x.blockSize-v] = b ^ byte(i)
		if x.oracle(tmp, buf) {
			return byte(i), nil
		}
	}
	return 0, errors.New("breakPaddingByte: nothing found")
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

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := Minimum(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// Minimum returns the smallest of a list of integers.
func Minimum(n int, nums ...int) int {
	for _, m := range nums {
		if m < n {
			n = m
		}
	}
	return n
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}
