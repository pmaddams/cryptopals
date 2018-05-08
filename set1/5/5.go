package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const secret = "ICE"

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

// XORCipher is a repeating XOR cipher.
type XORCipher struct {
	key []byte
}

// NewCipher creates a new XOR cipher.
func NewCipher(key []byte) *XORCipher {
	return &XORCipher{key}
}

// Crypt encrypts or decrypts a buffer.
func (x *XORCipher) Crypt(dst, src []byte) {
	for {
		n := XORBytes(dst, src, x.key)
		if n == 0 {
			break
		}
		src = src[n:]
		dst = dst[n:]
	}
}

// printEncrypted reads plaintext and prints hex-encoded ciphertext.
func (x *XORCipher) printEncrypted(in io.Reader) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	// Encrypt the data in place.
	x.Crypt(buf, buf)

	// Print the hex-encoded buffer.
	fmt.Println(hex.EncodeToString(buf))
}

func main() {
	x := NewCipher([]byte(secret))
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		x.printEncrypted(os.Stdin)
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		x.printEncrypted(f)
		f.Close()
	}
}
