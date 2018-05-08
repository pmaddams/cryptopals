package main

import "crypto/cipher"

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// XORBytes produces the XOR combination of two buffers.
func XORBytes(out, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		out[i] = b1[i] ^ b2[i]
	}
	return n
}

// xorCipher implements the cipher.Block interface,
// providing block encryption and decryption.
type xorCipher struct {
	key []byte
}

// NewCipher creates a new repeating XOR cipher.
func NewCipher(key []byte) (cipher.Block, error) {
	return &xorCipher{key}, nil
}

// BlockSize returns the XOR cipher block size.
func (c *xorCipher) BlockSize() int {
	return len(c.key)
}

// Encrypt encrypts a buffer with the XOR cipher.
func (c *xorCipher) Encrypt(dst, src []byte) {
	XORBytes(dst, src, c.key)
}

// Decrypt decrypts a buffer with the XOR cipher.
// In this case, it is identical to Encrypt.
func (c *xorCipher) Decrypt(dst, src []byte) {
	c.Encrypt(dst, src)
}

func main() {
}
