// 25. Break "random access read/write" AES CTR

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const secret = "YELLOW SUBMARINE"

func main() {
	files := os.Args[1:]
	if len(files) == 0 {
		if err := decryptCTR(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := decryptCTR(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// decryptCTR generates a CTR editor from base64-encoded,
// ECB-encrypted input, breaks it, and prints the plaintext.
func decryptCTR(in io.Reader) error {
	buf, err := decryptECB(in)
	if err != nil {
		return err
	}
	x, err := newCTREditor(buf)
	if err != nil {
		return err
	}
	buf, err = breakCTR(x)
	if err != nil {
		return err
	}
	fmt.Print(string(buf))

	return nil
}

// ctrEditor permits random-access CTR editing.
type ctrEditor struct {
	c          cipher.Block
	iv         []byte
	ciphertext []byte
}

// newCTREditor takes a buffer and creates a CTR editor with a random key.
func newCTREditor(buf []byte) (*ctrEditor, error) {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		return nil, err
	}
	iv := RandomBytes(aes.BlockSize)
	stream := cipher.NewCTR(c, iv)
	stream.XORKeyStream(buf, buf)

	return &ctrEditor{c, iv, buf}, nil
}

// breakCTR decrypts and returns the ciphertext.
func breakCTR(x *ctrEditor) ([]byte, error) {
	ciphertext := x.show()
	if err := x.edit(ciphertext, 0); err != nil {
		return nil, err
	}
	return x.show(), nil
}

// show returns a read-only copy of the ciphertext.
func (x *ctrEditor) show() []byte {
	return append([]byte{}, x.ciphertext...)
}

// edit takes new plaintext and an offset, and edits the ciphertext.
func (x *ctrEditor) edit(plaintext []byte, offset int) error {
	if offset < 0 || offset > len(x.ciphertext) {
		return errors.New("edit: invalid offset")
	}
	// Decrypt before copying the new data.
	stream := cipher.NewCTR(x.c, x.iv)
	stream.XORKeyStream(x.ciphertext, x.ciphertext)

	if len(x.ciphertext) < offset+len(plaintext) {
		x.ciphertext = append(x.ciphertext[:offset], plaintext...)
	} else {
		copy(x.ciphertext[offset:], plaintext)
	}
	target := x.ciphertext[offset : offset+len(plaintext)]

	// Regenerate the stream cipher.
	stream = cipher.NewCTR(x.c, x.iv)
	stream.XORKeyStream(target, target)
	return nil
}

// decryptECB takes base64-encoded, ECB-encrypted input and returns the plaintext.
func decryptECB(in io.Reader) ([]byte, error) {
	in = base64.NewDecoder(base64.StdEncoding, in)
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}
	NewECBDecrypter(c).CryptBlocks(buf, buf)
	buf, err = PKCS7Unpad(buf, c.BlockSize())
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ecbDecrypter represents an ECB decryption block mode.
type ecbDecrypter struct{ cipher.Block }

// NewECBDecrypter returns a block mode for ECB decryption.
func NewECBDecrypter(c cipher.Block) cipher.BlockMode {
	return ecbDecrypter{c}
}

// CryptBlocks decrypts a buffer in ECB mode.
func (x ecbDecrypter) CryptBlocks(dst, src []byte) {
	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for n := x.BlockSize(); len(src) > 0; {
		x.Decrypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
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

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}
