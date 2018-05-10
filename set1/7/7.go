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

// ECB wraps cipher.Block.
type ECB struct {
	cipher.Block
}

// NewECB creates a new ECB block mode.
func NewECB(b cipher.Block) ECB {
	return ECB{b}
}

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// cryptBlocks unsafely attempts to operate on multiple blocks.
func (x ECB) cryptBlocks(dst, src []byte, f func([]byte, []byte)) {
	for i := 0; i < min(len(dst), len(src))/x.BlockSize(); i++ {
		f(dst[i*x.BlockSize():], src[i*x.BlockSize():])
	}
}

// EncryptBlocks encrypts with cryptBlocks.
func (x ECB) EncryptBlocks(dst, src []byte) {
	x.cryptBlocks(dst, src, x.Encrypt)
}

// DecryptBlocks decrypts with cryptBlocks.
func (x ECB) DecryptBlocks(dst, src []byte) {
	x.cryptBlocks(dst, src, x.Decrypt)
}

// encryptAndPrint reads plaintext and prints base64-encoded ciphertext.
func (x ECB) encryptAndPrint(in io.Reader) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	// Encrypt in place.
	x.EncryptBlocks(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func (x ECB) decryptAndPrint(in io.Reader) {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	// Decrypt in place.
	x.DecryptBlocks(buf, buf)
	fmt.Println(string(buf))
}

var e = flag.Bool("e", false, "encrypt")

func main() {
	b, err := aes.NewCipher([]byte(secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	x := NewECB(b)

	flag.Parse()
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if *e {
			x.encryptAndPrint(os.Stdin)
		} else {
			x.decryptAndPrint(os.Stdin)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		if *e {
			x.encryptAndPrint(f)
		} else {
			x.decryptAndPrint(f)
		}
		f.Close()
	}
}
