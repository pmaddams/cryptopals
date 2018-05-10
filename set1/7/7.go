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

type ecb struct{ cipher.Block }

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// cryptBlocks unsafely attempts to operate on multiple blocks.
func (x ecb) cryptBlocks(dst, src []byte, f func([]byte, []byte)) {
	for n := x.BlockSize(); len(src) >= n; {
		f(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

type ecbEncrypter struct{ ecb }

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return ecbEncrypter{ecb{b}}
}

func (x ecbEncrypter) CryptBlocks(dst, src []byte) {
	x.cryptBlocks(dst, src, x.Encrypt)
}

type ecbDecrypter struct{ ecb }

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return ecbDecrypter{ecb{b}}
}

func (x ecbDecrypter) CryptBlocks(dst, src []byte) {
	x.cryptBlocks(dst, src, x.Decrypt)
}

// encryptAndPrint reads plaintext and prints base64-encoded ciphertext.
func encryptAndPrint(in io.Reader, b cipher.Block) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	NewECBEncrypter(b).CryptBlocks(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, b cipher.Block) {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	NewECBDecrypter(b).CryptBlocks(buf, buf)
	fmt.Println(string(buf))
}

var e = flag.Bool("e", false, "encrypt")

func main() {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	flag.Parse()
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if *e {
			encryptAndPrint(os.Stdin, block)
		} else {
			decryptAndPrint(os.Stdin, block)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		if *e {
			encryptAndPrint(f, block)
		} else {
			decryptAndPrint(f, block)
		}
		f.Close()
	}
}
