package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const secret = "YELLOW SUBMARINE"

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

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

// cbc contains a block cipher and initialization vector.
type cbc struct {
	b  cipher.Block
	iv []byte
}

// BlockSize returns the block size of the cipher.
func (x cbc) BlockSize() int {
	return x.b.BlockSize()
}

// cbcEncrypter embeds cbc.
type cbcEncrypter struct{ cbc }

// NewCBCEncrypter returns a cipher.BlockMode that encrypts in CBC mode.
func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	if block.BlockSize() != len(iv) {
		panic("NewCBCEncrypter: initialization vector length must equal block size")
	}
	return cbcEncrypter{cbc{block, iv}}
}

// cbcEncrypter.CryptBlocks implements CBC encryption for multiple blocks.
// In this case, it intentionally violates the cipher.BlockMode specification
// by allowing the source buffer to not be a multiple of the block size.
func (mode cbcEncrypter) CryptBlocks(dst, src []byte) {
	for n := mode.BlockSize(); len(src) >= n; {
		XORBytes(dst, src, mode.iv)
		mode.b.Encrypt(dst[:n], src[:n])
		copy(mode.iv, dst[:n])
		dst, src = dst[n:], src[n:]
	}
}

// cbcDecrypter embeds cbc.
type cbcDecrypter struct{ cbc }

// NewCBCDecrypter returns a cipher.BlockMode that decrypts in CBC mode.
func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	if block.BlockSize() != len(iv) {
		panic("NewCBCDecrypter: initialization vector length must equal block size")
	}
	return cbcDecrypter{cbc{block, iv}}
}

// cbcDecrypter.CryptBlocks implements CBC decryption for multiple blocks.
// In this case, it intentionally violates the cipher.BlockMode specification
// by allowing the source buffer to not be a multiple of the block size.
func (mode cbcDecrypter) CryptBlocks(dst, src []byte) {
	n := mode.BlockSize()
	tmp := make([]byte, n)

	for len(src) >= n {
		// Save the ciphertext as the new initialization vector.
		copy(tmp, src[:n])
		mode.b.Decrypt(dst[:n], src[:n])
		XORBytes(dst, dst, mode.iv)
		copy(mode.iv, tmp)
		dst, src = dst[n:], src[n:]
	}
}

// encryptAndPrint reads plaintext and prints base64-encoded ciphertext.
func encryptAndPrint(in io.Reader, mode cipher.BlockMode) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	mode.CryptBlocks(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, mode cipher.BlockMode) {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	mode.CryptBlocks(buf, buf)
	fmt.Println(string(buf))
}

var e = flag.Bool("e", false, "encrypt")

func main() {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	iv := make([]byte, aesBlockSize)

	flag.Parse()
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if *e {
			mode := NewCBCEncrypter(block, iv)
			encryptAndPrint(os.Stdin, mode)
		} else {
			mode := NewCBCDecrypter(block, iv)
			decryptAndPrint(os.Stdin, mode)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		if *e {
			mode := NewCBCEncrypter(block, iv)
			encryptAndPrint(f, mode)
		} else {
			mode := NewCBCDecrypter(block, iv)
			decryptAndPrint(f, mode)
		}
		f.Close()
	}
}
