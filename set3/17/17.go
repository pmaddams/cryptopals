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

// randomLine returns a random line from a file containing base64-encoded strings.
func randomLine(filename string) ([]byte, error) {
	f, err := os.Open(filename)
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
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	s := lines[weak.Intn(len(lines))]

	return base64.StdEncoding.DecodeString(s)
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

// ValidPadding returns true if a buffer has valid PKCS#7 padding.
func ValidPadding(buf []byte, blockSize int) bool {
	if _, err := PKCS7Unpad(buf, blockSize); err != nil {
		return false
	}
	return true
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// encryptedRandomLine returns an encrypted random line and corresponding
// initialization vector from a file containing base64-encoded strings.
func encryptedRandomLine(filename string, c cipher.Block) ([]byte, []byte, error) {
	buf, err := randomLine(filename)
	if err != nil {
		return nil, nil, err
	}
	iv := RandomBytes(c.BlockSize())
	mode := cipher.NewCBCEncrypter(c, iv)
	buf = PKCS7Pad(buf, mode.BlockSize())
	mode.CryptBlocks(buf, buf)
	return iv, buf, nil
}

// decryptedValidPadding returns true if a decrypted buffer has valid PKCS#7 padding.
func decryptedValidPadding(iv, buf []byte, c cipher.Block) bool {
	mode := cipher.NewCBCDecrypter(c, iv)
	tmp := make([]byte, len(buf))
	mode.CryptBlocks(tmp, buf)
	return ValidPadding(tmp, mode.BlockSize())
}

// cbcPaddingOracle returns a CBC padding oracle.
func cbcPaddingOracle(c cipher.Block) func([]byte, []byte) error {
	return func(iv, buf []byte) error {
		if !decryptedValidPadding(iv, buf, c) {
			return errors.New("psst...invalid padding")
		}
		return nil
	}
}

// cbcBreaker contains data necessary to attack the CBC padding oracle.
type cbcBreaker struct {
	oracle     func([]byte, []byte) error
	iv         []byte
	ciphertext []byte
	blockSize  int
}

// newCBCBreaker takes a CBC padding oracle, IV, and ciphertext, and returns a breaker.
func newCBCBreaker(oracle func([]byte, []byte) error, iv, ciphertext []byte) *cbcBreaker {
	return &cbcBreaker{
		oracle:     oracle,
		iv:         iv,
		ciphertext: ciphertext,
		blockSize:  len(iv),
	}
}

// breakPaddingByte returns the plaintext byte for the given padding value.
func (x *cbcBreaker) breakPaddingByte(tmp, buf []byte, v int) (byte, error) {
	b := tmp[x.blockSize-v]

	// Iterate backwards to avoid restoring an original padding byte.
	for i := 0xff; i >= 0; i-- {
		tmp[x.blockSize-v] = b ^ byte(i)

		// If the oracle does not return an error,
		// we have found a byte of plaintext.
		if err := x.oracle(tmp, buf); err == nil {
			return byte(i), nil
		}
	}
	return 0, errors.New("breakPaddingByte: nothing found")
}

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
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

// breakOracle breaks the padding oracle and returns the plaintext.
func (x *cbcBreaker) breakOracle() ([]byte, error) {
	blocks := Blocks(x.ciphertext, x.blockSize)
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

func main() {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	iv, ciphertext, err := encryptedRandomLine("17.txt", c)
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
