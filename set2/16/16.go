package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// UserData returns a string with arbitrary data inserted in the middle.
func UserData(s string) string {
	const prefix = "comment1=cooking%20MCs;userdata="
	const suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	return prefix + url.QueryEscape(s) + suffix
}

// AdminTrue returns true if a semicolon-separated string contains "admin=true".
func AdminTrue(s string) bool {
	for _, v := range strings.Split(s, ";") {
		if v == "admin=true" {
			return true
		}
	}
	return false
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

// decryptedAdminTrue returns true if a decrypted semicolon-separated string contains "admin=true".
func decryptedAdminTrue(buf []byte, dec cipher.BlockMode) bool {
	tmp := make([]byte, len(buf))
	dec.CryptBlocks(tmp, buf)
	tmp, err := PKCS7Unpad(tmp, dec.BlockSize())
	if err != nil {
		return false
	}
	return AdminTrue(string(tmp))
}

// xorMaskByte returns an XOR mask that prevents query escaping for the target byte.
func xorMaskByte(b byte) byte {
	var res byte
	for i := 0; i < 256; i++ {
		s := string(b ^ byte(i))
		if s == url.QueryEscape(s) {
			res = byte(i)
			break
		}
	}
	return res
}

// xorMask returns an XOR mask that prevents query escaping for the target buffer.
func xorMask(buf []byte) []byte {
	var res []byte
	for _, b := range buf {
		res = append(res, xorMaskByte(b))
	}
	return res
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
	b, err := aes.NewCipher(RandomBytes(aesBlockSize))
	if err != nil {
		panic(err)
	}
	iv := RandomBytes(b.BlockSize())

	enc := cipher.NewCBCEncrypter(b, iv)
	dec := cipher.NewCBCDecrypter(b, iv)

	data := []byte("XXXXX;admin=true")
	mask := xorMask(data)
	XORBytes(data, data, mask)

	buf := encryptedUserData(string(data), enc)
	target := buf[aesBlockSize : 2*aesBlockSize]
	XORBytes(target, target, mask)

	if decryptedAdminTrue(buf, dec) {
		fmt.Println("success")
	}
}
