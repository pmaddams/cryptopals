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

// cryptBlocks encrypts or decrypts multiple blocks.
func (x ecb) cryptBlocks(dst, src []byte, crypt func([]byte, []byte)) {
	if len(src)%x.BlockSize() != 0 {
		panic("cryptBlocks: input not full blocks")
	}
	for n := x.BlockSize(); len(src) > 0; {
		crypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

// ecbEncrypter embeds ecb.
type ecbEncrypter struct{ ecb }

// NewECBEncrypter returns a block mode for ECB encryption.
func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return ecbEncrypter{ecb{block}}
}

// ecbEncrypter.CryptBlocks encrypts multiple blocks.
func (mode ecbEncrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.b.Encrypt)
}

// ecbDecrypter embeds ecb.
type ecbDecrypter struct{ ecb }

// NewECBEncrypter returns a block mode for ECB decryption.
func NewECBDecrypter(block cipher.Block) cipher.BlockMode {
	return ecbDecrypter{ecb{block}}
}

// ecbDecrypter.CryptBlocks decrypts multiple blocks.
func (mode ecbDecrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.b.Decrypt)
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	var n int

	// If the buffer length is a multiple of the block size,
	// add a number of padding bytes equal to the block size.
	if rem := len(buf) % blockSize; rem == 0 {
		n = blockSize
	} else {
		n = blockSize - rem
	}
	for i := 0; i < n; i++ {
		buf = append(buf, byte(n))
	}
	return buf
}

// PKCS7Unpad returns a buffer with PKCS#7 padding removed.
func PKCS7Unpad(buf []byte, blockSize int) ([]byte, error) {
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	if int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	return buf[:len(buf)-int(b)], nil
}

// encryptAndPrint reads plaintext and prints base64-encoded ciphertext.
func encryptAndPrint(in io.Reader, block cipher.Block) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	buf = PKCS7Pad(buf, block.BlockSize())
	NewECBEncrypter(block).CryptBlocks(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, block cipher.Block) {
	in = base64.NewDecoder(base64.StdEncoding, in)
	var buf []byte
	var err error
	if buf, err = ioutil.ReadAll(in); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	NewECBDecrypter(block).CryptBlocks(buf, buf)
	if buf, err = PKCS7Unpad(buf, block.BlockSize()); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	fmt.Print(string(buf))
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
