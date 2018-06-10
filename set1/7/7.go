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

// ecb embeds cipher.Block, hiding its methods.
type ecb struct{ b cipher.Block }

// BlockSize returns the block size of the cipher.
func (x ecb) BlockSize() int {
	return x.b.BlockSize()
}

// cryptBlocks encrypts or decrypts a buffer in ECB mode.
func (x ecb) cryptBlocks(dst, src []byte, crypt func([]byte, []byte)) {
	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for n := x.BlockSize(); len(src) > 0; {
		crypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

// ecbEncrypter embeds ecb.
type ecbEncrypter struct{ ecb }

// NewECBEncrypter returns a block mode for ECB encryption.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return ecbEncrypter{ecb{b}}
}

// ecbEncrypter.CryptBlocks encrypts a buffer in ECB mode.
func (mode ecbEncrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.b.Encrypt)
}

// ecbDecrypter embeds ecb.
type ecbDecrypter struct{ ecb }

// NewECBDecrypter returns a block mode for ECB decryption.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return ecbDecrypter{ecb{b}}
}

// ecbDecrypter.CryptBlocks decrypts a buffer in ECB mode.
func (mode ecbDecrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.b.Decrypt)
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 0xff {
		panic("PKCS7Pad: invalid block size")
	}
	// Find the number (and value) of padding bytes.
	n := blockSize - (len(buf) % blockSize)

	return append(buf, bytes.Repeat([]byte{byte(n)}, n)...)
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
	return buf[:len(buf)-int(b)], nil
}

// encryptAndPrint reads plaintext and prints base64-encoded ciphertext.
func encryptAndPrint(in io.Reader, b cipher.Block) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	buf = PKCS7Pad(buf, b.BlockSize())
	NewECBEncrypter(b).CryptBlocks(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, b cipher.Block) {
	in = base64.NewDecoder(base64.StdEncoding, in)
	var buf []byte
	var err error
	if buf, err = ioutil.ReadAll(in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	NewECBDecrypter(b).CryptBlocks(buf, buf)
	if buf, err = PKCS7Unpad(buf, b.BlockSize()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Print(string(buf))
}

var e = flag.Bool("e", false, "encrypt")

func main() {
	b, err := aes.NewCipher([]byte(secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	flag.Parse()
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if *e {
			encryptAndPrint(os.Stdin, b)
		} else {
			decryptAndPrint(os.Stdin, b)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if *e {
			encryptAndPrint(f, b)
		} else {
			decryptAndPrint(f, b)
		}
		f.Close()
	}
}
