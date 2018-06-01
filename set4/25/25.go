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

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// ecbDecrypter embeds cipher.Block, hiding its methods.
type ecbDecrypter struct{ b cipher.Block }

// NewECBDecrypter returns a block mode for ECB Decryption.
func NewECBDecrypter(block cipher.Block) cipher.BlockMode {
	return ecbDecrypter{block}
}

// BlockSize returns the block size of the cipher.
func (mode ecbDecrypter) BlockSize() int {
	return mode.b.BlockSize()
}

// CryptBlocks decrypts a buffer in ECB mode.
func (mode ecbDecrypter) CryptBlocks(dst, src []byte) {
	// The src buffer length must be a multiple of the block size,
	// and the dst buffer must be at least the length of src.
	for n := mode.BlockSize(); len(src) > 0; {
		mode.b.Decrypt(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]
	}
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

// decodeAndDecrypt takes base64-encoded, encrypted input and returns the plaintext.
func decodeAndDecrypt(in io.Reader) ([]byte, error) {
	in = base64.NewDecoder(base64.StdEncoding, in)
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}
	NewECBDecrypter(block).CryptBlocks(buf, buf)
	buf, err = PKCS7Unpad(buf, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// CTREditor permits random-access CTR editing.
type CTREditor struct {
	block      cipher.Block
	iv         []byte
	ciphertext []byte
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(length int) []byte {
	res := make([]byte, length)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
}

// NewCTREditor takes base64-encoded, encrypted input and returns a CTREditor.
func NewCTREditor(in io.Reader) (*CTREditor, error) {
	buf, err := decodeAndDecrypt(in)
	block, err := aes.NewCipher(RandomBytes(aesBlockSize))
	if err != nil {
		return nil, err
	}
	iv := RandomBytes(aesBlockSize)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(buf, buf)

	return &CTREditor{block, iv, buf}, nil
}

// Edit takes new plaintext and an offset, and edits the ciphertext.
func (e *CTREditor) Edit(plaintext []byte, offset int) {
	stream := cipher.NewCTR(e.block, e.iv)
	stream.XORKeyStream(e.ciphertext, e.ciphertext)
	if len(e.ciphertext) < offset+len(plaintext) {
		e.ciphertext = append(e.ciphertext[:offset], plaintext...)
	} else {
		copy(e.ciphertext[offset:], plaintext)
	}
	target := e.ciphertext[offset : offset+len(plaintext)]
	stream = cipher.NewCTR(e.block, e.iv)
	stream.XORKeyStream(target, target)
}

// Show returns a read-only copy of the ciphertext.
func (e *CTREditor) Show() []byte {
	return append([]byte{}, e.ciphertext...)
}

// breakCTREditor decrypts and returns the ciphertext.
func breakCTREditor(e *CTREditor) []byte {
	ciphertext := e.Show()
	e.Edit(ciphertext, 0)
	return e.Show()
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		e, err := NewCTREditor(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		fmt.Print(string(breakCTREditor(e)))
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		e, err := NewCTREditor(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		fmt.Print(string(breakCTREditor(e)))
		f.Close()
	}
}
