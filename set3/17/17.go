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

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

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

// ValidPadding returns true if a buffer has valid PKCS#7 padding.
func ValidPadding(buf []byte, blockSize int) bool {
	if _, err := PKCS7Unpad(buf, blockSize); err != nil {
		return false
	}
	return true
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

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(length int) []byte {
	res := make([]byte, length)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
}

// encryptedRandomLine returns an encrypted random line and corresponding
// initialization vector from a file containing base64-encoded strings.
func encryptedRandomLine(filename string, block cipher.Block) ([]byte, []byte, error) {
	buf, err := randomLine(filename)
	if err != nil {
		return nil, nil, err
	}
	iv := RandomBytes(aesBlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	buf = PKCS7Pad(buf, mode.BlockSize())
	mode.CryptBlocks(buf, buf)
	return iv, buf, nil
}

// decryptedValidPadding returns true if a decrypted buffer has valid PKCS#7 padding.
func decryptedValidPadding(iv, buf []byte, block cipher.Block) bool {
	mode := cipher.NewCBCDecrypter(block, iv)
	tmp := make([]byte, len(buf))
	mode.CryptBlocks(tmp, buf)
	return ValidPadding(tmp, mode.BlockSize())
}

// cbcPaddingOracle returns a CBC padding oracle function.
func cbcPaddingOracle(block cipher.Block) func([]byte, []byte) error {
	return func(iv, buf []byte) error {
		if !decryptedValidPadding(iv, buf, block) {
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

	// We have to iterate backwards to avoid restoring
	// an original padding byte in the final block.
	for i := 255; i >= 0; i-- {
		tmp[x.blockSize-v] = b ^ byte(i)

		// If the oracle does not return an error,
		// we have found a byte of plaintext.
		if err := x.oracle(tmp, buf); err == nil {
			return byte(i), nil
		}
	}
	return byte(0), errors.New("breakPaddingByte: nothing found")
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

// breakOracle breaks the padding oracle and returns the plaintext.
func (x *cbcBreaker) breakOracle() ([]byte, error) {
	n := len(x.ciphertext) / x.blockSize
	blocks := make([][]byte, n)
	for i := 0; i < n; i++ {
		blocks[i] = x.ciphertext[i*x.blockSize : (i+1)*x.blockSize]
	}
	res, err := x.breakBlock(x.iv, blocks[0])
	if err != nil {
		return nil, err
	}
	for i := 1; i < n; i++ {
		buf, err := x.breakBlock(blocks[i-1], blocks[i])
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}
	res, err = PKCS7Unpad(res, x.blockSize)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func main() {
	block := RandomCipher()
	iv, ciphertext, err := encryptedRandomLine("17.txt", block)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	oracle := cbcPaddingOracle(block)
	x := newCBCBreaker(oracle, iv, ciphertext)

	buf, err := x.breakOracle()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Println(string(buf))
}
