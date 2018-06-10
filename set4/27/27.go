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

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// UserData returns a string with arbitrary data inserted in the middle.
func UserData(s string) string {
	const prefix = "comment1=cooking%20MCs;userdata="
	const suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	return prefix + url.QueryEscape(s) + suffix
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 0xff {
		panic("PKCS7Pad: invalid block size")
	}
	// Find the number (and value) of padding bytes.
	n := blockSize - (len(buf) % blockSize)

	return append(buf, bytes.Repeat([]byte{byte(n)}, n)...)
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

// encryptedUserData returns an encrypted string with arbitrary data inserted in the middle.
func encryptedUserData(s string, enc cipher.BlockMode) []byte {
	buf := PKCS7Pad([]byte(UserData(s)), enc.BlockSize())
	enc.CryptBlocks(buf, buf)
	return buf
}

// Blocks divides a buffer into blocks.
func Blocks(buf []byte, n int) [][]byte {
	var res [][]byte
	for len(buf) >= n {
		// Return pointers, not copies.
		res = append(res, buf[:n])
		buf = buf[n:]
	}
	return res
}

// validate returns an error containing the plaintext, if it is invalid.
func validate(buf []byte, dec cipher.BlockMode) error {
	out := make([]byte, len(buf))
	dec.CryptBlocks(out, buf)
	_, err := PKCS7Unpad(out, dec.BlockSize())
	if err != nil || !utf8.Valid(out) {
		return errors.New(strconv.Quote(string(out)))
	}
	return nil
}

// clear overwrites a buffer with zeroes.
func clear(buf []byte) {
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

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

func main() {
	key := RandomBytes(aesBlockSize)
	fmt.Println(strconv.Quote(string(key)))

	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	enc := cipher.NewCBCEncrypter(b, key)
	dec := cipher.NewCBCDecrypter(b, key)

	ciphertext := encryptedUserData("", enc)
	blocks := Blocks(ciphertext, aesBlockSize)
	copy(blocks[2], blocks[0])
	clear(blocks[1])

	err = validate(ciphertext, dec)
	if err == nil {
		fmt.Fprintln(os.Stderr, "no error")
		return
	}
	plaintext, err := strconv.Unquote(err.Error())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	blocks = Blocks([]byte(plaintext), aesBlockSize)
	XORBytes(blocks[0], blocks[0], blocks[2])
	fmt.Println(strconv.Quote(string(blocks[0])))
}
