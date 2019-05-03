// 27. Recover the key from CBC with IV=Key

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"unicode/utf8"
)

func main() {
	key := RandomBytes(aes.BlockSize)
	fmt.Println(strconv.Quote(string(key)))

	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	enc := cipher.NewCBCEncrypter(c, key)
	dec := cipher.NewCBCDecrypter(c, key)

	ciphertext := cbcUserData("", enc)
	blocks := Subdivide(ciphertext, aes.BlockSize)
	copy(blocks[2], blocks[0])
	clear(blocks[1])

	err = validate(ciphertext, dec)
	if err == nil {
		fmt.Fprintln(os.Stderr, "no error")
		return
	}
	plaintext, err := strconv.Unquote(err.Error())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	blocks = Subdivide([]byte(plaintext), aes.BlockSize)
	XORBytes(blocks[0], blocks[0], blocks[2])
	fmt.Println(strconv.Quote(string(blocks[0])))
}

// cbcUserData returns an encrypted string with arbitrary data inserted in the middle.
func cbcUserData(s string, enc cipher.BlockMode) []byte {
	buf := PKCS7Pad([]byte(UserData(s)), enc.BlockSize())
	enc.CryptBlocks(buf, buf)
	return buf
}

// UserData returns a string with arbitrary data inserted in the middle.
func UserData(s string) string {
	const (
		prefix = "comment1=cooking%20MCs;userdata="
		suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	)
	return prefix + url.QueryEscape(s) + suffix
}

// validate returns an error containing the plaintext if it is invalid.
func validate(buf []byte, dec cipher.BlockMode) error {
	out := make([]byte, len(buf))
	dec.CryptBlocks(out, buf)
	_, err := PKCS7Unpad(out, dec.BlockSize())
	if err != nil || !utf8.Valid(out) {
		return errors.New(strconv.Quote(string(out)))
	}
	return nil
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
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}

// clear overwrites a buffer with zeroes.
func clear(buf []byte) {
	// The compiler should optimize this loop.
	for i := range buf {
		buf[i] = 0
	}
}

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}
