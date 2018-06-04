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
func RandomBytes(length int) []byte {
	res := make([]byte, length)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
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

// Vis converts a buffer to a string with non-printing bytes hex-encoded.
func Vis(buf []byte) string {
	var out []byte
	for _, b := range buf {
		if b >= 32 && b <= 125 {
			out = append(out, b)
		} else {
			out = append(out, fmt.Sprintf("\\x%02x", b)...)
		}
	}
	return string(out)
}

// Unvis converts a string to a buffer with hex-encoded bytes decoded.
func Unvis(s string) ([]byte, error) {
	s, err := strconv.Unquote(`"` + s + `"`)
	return []byte(s), err
}

// sillyErrorMessage returns an error containing the plaintext if it is invalid.
func sillyErrorMessage(buf []byte, dec cipher.BlockMode) error {
	tmp := make([]byte, len(buf))
	dec.CryptBlocks(tmp, buf)
	if _, err := PKCS7Unpad(tmp, dec.BlockSize()); err != nil {
		return errors.New(Vis(tmp))
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
	fmt.Println("key:", Vis(key))

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	enc := cipher.NewCBCEncrypter(block, key)
	dec := cipher.NewCBCEncrypter(block, key)

	buf := encryptedUserData("XXXXXXXXXXXXXXXX", enc)
	copy(buf[2*aesBlockSize:3*aesBlockSize], buf[:aesBlockSize])
	clear(buf[aesBlockSize : 2*aesBlockSize])

	err = sillyErrorMessage(buf, dec)
	plaintext, err := Unvis(err.Error())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	keyCopy := make([]byte, aesBlockSize)
	XORBytes(keyCopy, plaintext[:aesBlockSize], plaintext[2*aesBlockSize:3*aesBlockSize])
	fmt.Println("copy:", Vis(keyCopy))
}
