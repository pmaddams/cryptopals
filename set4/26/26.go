package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
)

// UserData returns a string with arbitrary data inserted in the middle.
func UserData(s string) string {
	const (
		prefix = "comment1=cooking%20MCs;userdata="
		suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	)
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
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// encryptedUserData returns an encrypted string with arbitrary data inserted in the middle.
func encryptedUserData(s string, c cipher.Block, iv []byte) []byte {
	buf := []byte(UserData(s))
	cipher.NewCTR(c, iv).XORKeyStream(buf, buf)
	return buf
}

// decryptedAdminTrue returns true if a decrypted semicolon-separated string contains "admin=true".
func decryptedAdminTrue(buf []byte, c cipher.Block, iv []byte) bool {
	tmp := make([]byte, len(buf))
	cipher.NewCTR(c, iv).XORKeyStream(tmp, buf)
	return AdminTrue(string(tmp))
}

// xorMaskByte returns an XOR mask that prevents query escaping for the target byte.
func xorMaskByte(b byte) byte {
	var res byte
	for i := 0; i <= 0xff; i++ {
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
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	iv := RandomBytes(c.BlockSize())

	data := []byte("XXXXX;admin=true")
	mask := xorMask(data)
	XORBytes(data, data, mask)

	buf := encryptedUserData(string(data), c, iv)
	target := buf[2*aes.BlockSize : 3*aes.BlockSize]
	XORBytes(target, target, mask)

	if decryptedAdminTrue(buf, c, iv) {
		fmt.Println("success")
	}
}
