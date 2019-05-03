// 26. CTR bitflipping

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
)

func main() {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	iv := RandomBytes(c.BlockSize())

	data := []byte("XXXXX;admin=true")
	mask := xorMask(data)
	XORBytes(data, data, mask)

	buf := ctrUserData(string(data), c, iv)
	target := buf[2*aes.BlockSize : 3*aes.BlockSize]
	XORBytes(target, target, mask)

	if ctrIsAdmin(buf, c, iv) {
		fmt.Println("success")
	}
}

// xorMask returns an XOR mask that prevents query escaping for the target buffer.
func xorMask(buf []byte) []byte {
	res := make([]byte, len(buf))
	for i, b := range buf {
		for j := 0; j <= 0xff; j++ {
			if s := string(b ^ byte(j)); s == url.QueryEscape(s) {
				res[i] = byte(j)
				break
			}
		}
	}
	return res
}

// ctrUserData returns an encrypted string with arbitrary data inserted in the middle.
func ctrUserData(s string, c cipher.Block, iv []byte) []byte {
	buf := []byte(UserData(s))
	cipher.NewCTR(c, iv).XORKeyStream(buf, buf)
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

// ctrIsAdmin returns true if a decrypted semicolon-separated string contains "admin=true".
func ctrIsAdmin(buf []byte, c cipher.Block, iv []byte) bool {
	tmp := make([]byte, len(buf))
	cipher.NewCTR(c, iv).XORKeyStream(tmp, buf)
	return IsAdmin(string(tmp))
}

// IsAdmin returns true if a semicolon-separated string contains "admin=true".
func IsAdmin(s string) bool {
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

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}
