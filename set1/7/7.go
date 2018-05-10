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

// ecb embeds cipher.Block.
type ecb struct{ cipher.Block }

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// cryptBlocks unsafely attempts to execute a cipher on multiple blocks.
func (x ecb) cryptBlocks(dst, src []byte, crypt func([]byte, []byte)) {
	for n := x.BlockSize(); len(src) >= n; {
		crypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

// ecbEncrypter embeds ecb.
type ecbEncrypter struct{ ecb }

// NewECBEncrypter returns a BlockMode that encrypts in ECB mode.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return ecbEncrypter{ecb{b}}
}

// ecbEncrypter.CryptBlocks implements ECB encryption for multiple blocks.
// In this case, it intentionally violates the cipher.BlockMode specification
// by allowing the source buffer to not be a multiple of the block size.
func (x ecbEncrypter) CryptBlocks(dst, src []byte) {
	x.cryptBlocks(dst, src, x.Encrypt)
}

// ecbDecrypter embeds ecb.
type ecbDecrypter struct{ ecb }

// NewECBDecrypter returns a BlockMode that decrypts in ECB mode.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return ecbDecrypter{ecb{b}}
}

// ecbDecrypter.CryptBlocks implements ECB decryption for multiple blocks.
// In this case, it intentionally violates the cipher.BlockMode specification
// by allowing the source buffer to not be a multiple of the block size.
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
