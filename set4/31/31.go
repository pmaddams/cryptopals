package main

import (
	"bytes"
	"hash"
	"time"
)

const delay = 100*time.Millisecond

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

// hmac contains data for generating a hash-based message authentication code.
type hmac struct {
	hash.Hash
	ipad []byte
	opad []byte
	buf  *bytes.Buffer
}

// NewHMAC takes a hash and key, and returns a new HMAC hash.
func NewHMAC(f func() hash.Hash, key []byte) hash.Hash {
	h := f()
	// If the key is too long, hash it.
	if len(key) > h.BlockSize() {
		h.Write(key)
		key = h.Sum([]byte{})
		h.Reset()
	}
	ipad := bytes.Repeat([]byte{0x36}, h.BlockSize())
	opad := bytes.Repeat([]byte{0x5c}, h.BlockSize())

	XORBytes(opad, opad, key)
	XORBytes(ipad, ipad, key)

	return &hmac{h, ipad, opad, new(bytes.Buffer)}
}

// Reset resets the hash.
func (h *hmac) Reset() {
	h.buf.Reset()
}

// Write writes data to the hash.
func (h *hmac) Write(buf []byte) (int, error) {
	return h.buf.Write(buf)
}

// Sum appends a checksum to the given buffer.
func (h *hmac) Sum(buf []byte) []byte {
	h.Hash.Write(h.ipad)
	h.Hash.Write(h.buf.Bytes())

	sum := h.Hash.Sum([]byte{})
	h.Hash.Reset()

	h.Hash.Write(h.opad)
	h.Hash.Write(sum)

	sum = h.Hash.Sum([]byte{})
	h.Hash.Reset()

	return append(buf, sum...)
}

// insecureEqual checks if two buffers contain the same bytes,
// returning false immediately upon finding a mismatched pair.
func insecureEqual(b1, b2 []byte) bool {
	for len(b1) != 0 && len(b2) != 0 {
		if b1[0] != b2[0] {
			return false
		}
		b1, b2 = b1[1:], b2[1:]
		time.Sleep(delay)
	}
	return len(b1) == len(b2)
}

func main() {
}
