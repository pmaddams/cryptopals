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

// decryptedAdminTrue returns true if a decrypted semicolon-separated string contains "admin=true".
func decryptedAdminTrue(buf []byte, dec cipher.BlockMode) bool {
	dec.CryptBlocks(buf, buf)
	var err error
	if buf, err = PKCS7Unpad(buf, dec.BlockSize()); err != nil {
		return false
	}
	return AdminTrue(string(buf))
}

// byteMask returns an XOR mask that prevents query escaping for the target byte.
func byteMask(b byte) byte {
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

// blockMask returns an XOR mask that prevents query escaping for the target block.
func blockMask(buf []byte, blockSize int) ([]byte, error) {
	if len(buf) != blockSize {
		return nil, errors.New("blockMask: buffer length must be equal to block size")
	}
	res := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		res[i] = byteMask(buf[i])
	}
	return res, nil
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
	block := RandomCipher()
	iv := RandomBytes(aesBlockSize)

	enc := cipher.NewCBCEncrypter(block, iv)
	dec := cipher.NewCBCDecrypter(block, iv)

	data := []byte("XXXXX;admin=true")
	mask, err := blockMask(data, aesBlockSize)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	XORBytes(data, data, mask)

	buf := encryptedUserData(string(data), enc)
	target := buf[aesBlockSize : 2*aesBlockSize]
	XORBytes(target, target, mask)

	if decryptedAdminTrue(buf, dec) {
		fmt.Println("success")
	}
}
