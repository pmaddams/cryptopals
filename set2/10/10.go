package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const secret = "YELLOW SUBMARINE"

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

// cbc represents a generic CBC block mode.
type cbc struct {
	c  cipher.Block
	iv []byte
}

// BlockSize returns the cipher block size.
func (x cbc) BlockSize() int {
	return x.c.BlockSize()
}

// cbcEncrypter represents a CBC encryption block mode.
type cbcEncrypter struct{ cbc }

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}

// NewCBCEncrypter returns a block mode for CBC encryption.
func NewCBCEncrypter(c cipher.Block, iv []byte) cipher.BlockMode {
	if c.BlockSize() != len(iv) {
		panic("NewCBCEncrypter: initialization vector length must equal block size")
	}
	return cbcEncrypter{cbc{c, dup(iv)}}
}

// cbcEncrypter.CryptBlocks encrypts a buffer in CBC mode.
func (mode cbcEncrypter) CryptBlocks(dst, src []byte) {
	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for n := mode.BlockSize(); len(src) > 0; {
		XORBytes(dst, src, mode.iv)
		mode.c.Encrypt(dst[:n], src[:n])
		copy(mode.iv, dst[:n])
		dst, src = dst[n:], src[n:]
	}
}

// cbcDecrypter represents a CBC decryption block mode.
type cbcDecrypter struct{ cbc }

// NewCBCDecrypter returns a block mode for CBC decryption.
func NewCBCDecrypter(c cipher.Block, iv []byte) cipher.BlockMode {
	if c.BlockSize() != len(iv) {
		panic("NewCBCDecrypter: initialization vector length must equal block size")
	}
	return cbcDecrypter{cbc{c, iv}}
}

// cbcDecrypter.CryptBlocks decrypts a buffer in CBC mode.
func (mode cbcDecrypter) CryptBlocks(dst, src []byte) {
	n := mode.BlockSize()
	tmp := make([]byte, n)

	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for len(src) > 0 {
		// Save the ciphertext as the new initialization vector.
		copy(tmp, src[:n])
		mode.c.Decrypt(dst[:n], src[:n])
		XORBytes(dst, dst, mode.iv)
		copy(mode.iv, tmp)
		dst, src = dst[n:], src[n:]
	}
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 0xff {
		panic("PKCS7Pad: invalid block size")
	}
	// Find the number (and value) of padding bytes.
	n := blockSize - (len(buf) % blockSize)

	return append(dup(buf), bytes.Repeat([]byte{byte(n)}, n)...)
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
	return dup(buf)[:len(buf)-int(b)], nil
}

// encryptAndPrint reads plaintext and prints base64-encoded ciphertext.
func encryptAndPrint(in io.Reader, mode cipher.BlockMode) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	buf = PKCS7Pad(buf, mode.BlockSize())
	mode.CryptBlocks(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, mode cipher.BlockMode) {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	mode.CryptBlocks(buf, buf)
	if buf, err = PKCS7Unpad(buf, mode.BlockSize()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Print(string(buf))
}

var e = flag.Bool("e", false, "encrypt")

func main() {
	c, err := aes.NewCipher([]byte(secret))
	if err != nil {
		panic(err)
	}
	iv := make([]byte, c.BlockSize())

	flag.Parse()
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if *e {
			mode := NewCBCEncrypter(c, iv)
			encryptAndPrint(os.Stdin, mode)
		} else {
			mode := NewCBCDecrypter(c, iv)
			decryptAndPrint(os.Stdin, mode)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if *e {
			mode := NewCBCEncrypter(c, iv)
			encryptAndPrint(f, mode)
		} else {
			mode := NewCBCDecrypter(c, iv)
			decryptAndPrint(f, mode)
		}
		f.Close()
	}
}
