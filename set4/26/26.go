package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
func RandomBytes(length int) []byte {
	res := make([]byte, length)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
}

// encryptedUserData returns an encrypted string with arbitrary data inserted in the middle.
func encryptedUserData(s string, block cipher.Block, iv []byte) []byte {
	buf := []byte(UserData(s))
	cipher.NewCTR(block, iv).XORKeyStream(buf, buf)
	return buf
}

// decryptedAdminTrue returns true if a decrypted semicolon-separated string contains "admin=true".
func decryptedAdminTrue(buf []byte, block cipher.Block, iv []byte) bool {
	tmp := make([]byte, len(buf))
	cipher.NewCTR(block, iv).XORKeyStream(tmp, buf)
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
	block, err := aes.NewCipher(RandomBytes(aesBlockSize))
	if err != nil {
		panic(err.Error())
	}
	iv := RandomBytes(block.BlockSize())

	data := []byte("XXXXX;admin=true")
	mask := xorMask(data)
	XORBytes(data, data, mask)

	buf := encryptedUserData(string(data), block, iv)
	target := buf[2*aesBlockSize : 3*aesBlockSize]
	XORBytes(target, target, mask)

	if decryptedAdminTrue(buf, block, iv) {
		fmt.Println("success")
	}
}
