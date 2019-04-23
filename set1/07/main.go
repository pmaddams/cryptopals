// 7. AES in ECB mode

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

func main() {
	var (
		e  bool
		fn func(io.Reader, cipher.Block) error
	)
	flag.BoolVar(&e, "e", false, "encrypt")
	flag.Parse()
	if e {
		fn = encrypt
	} else {
		fn = decrypt
	}
	c, err := aes.NewCipher([]byte(secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	files := flag.Args()
	if len(files) == 0 {
		if err := fn(os.Stdin, c); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := fn(f, c); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// encrypt reads plaintext and prints base64-encoded ciphertext.
func encrypt(in io.Reader, c cipher.Block) error {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}
	buf = PKCS7Pad(buf, c.BlockSize())
	NewECBEncrypter(c).CryptBlocks(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))

	return nil
}

// decrypt reads base64-encoded ciphertext and prints plaintext.
func decrypt(in io.Reader, c cipher.Block) error {
	in = base64.NewDecoder(base64.StdEncoding, in)
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}
	NewECBDecrypter(c).CryptBlocks(buf, buf)
	buf, err = PKCS7Unpad(buf, c.BlockSize())
	if err != nil {
		return err
	}
	fmt.Print(string(buf))

	return nil
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
	errInvalidPadding := errors.New("PKCS7Unpad: invalid padding")
	if len(buf) < blockSize {
		return nil, errInvalidPadding
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	n := len(buf) - int(b)
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[n:]) {
		return nil, errInvalidPadding
	}
	return dup(buf[:n]), nil
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}

// ecb represents a generic ECB block mode.
type ecb struct{ cipher.Block }

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

// ecbEncrypter represents an ECB encryption block mode.
type ecbEncrypter struct{ ecb }

// NewECBEncrypter returns a block mode for ECB encryption.
func NewECBEncrypter(c cipher.Block) cipher.BlockMode {
	return ecbEncrypter{ecb{c}}
}

// ecbEncrypter.CryptBlocks encrypts a buffer in ECB mode.
func (x ecbEncrypter) CryptBlocks(dst, src []byte) {
	x.cryptBlocks(dst, src, x.Encrypt)
}

// ecbDecrypter represents an ECB decryption block mode.
type ecbDecrypter struct{ ecb }

// NewECBDecrypter returns a block mode for ECB decryption.
func NewECBDecrypter(c cipher.Block) cipher.BlockMode {
	return ecbDecrypter{ecb{c}}
}

// ecbDecrypter.CryptBlocks decrypts a buffer in ECB mode.
func (x ecbDecrypter) CryptBlocks(dst, src []byte) {
	x.cryptBlocks(dst, src, x.Decrypt)
}
