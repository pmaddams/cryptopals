package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	weak "math/rand"
	"os"
	"time"
)

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// randomLine returns a random line from a file containing base64-encoded strings.
func randomLine(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	input := bufio.NewScanner(f)
	var lines []string
	for input.Scan() {
		lines = append(lines, input.Text())
	}
	if err := input.Err(); err != nil {
		return nil, err
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	s := lines[weak.Intn(len(lines))]

	return base64.StdEncoding.DecodeString(s)
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
	if len(buf) < blockSize {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	if int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	return buf[:len(buf)-int(b)], nil
}

// ValidPadding returns true if a buffer has valid PKCS#7 padding.
func ValidPadding(buf []byte, blockSize int) bool {
	if _, err := PKCS7Unpad(buf, blockSize); err != nil {
		return false
	}
	return true
}

// RandomCipher returns an AES cipher with a random key.
func RandomCipher() cipher.Block {
	key := make([]byte, aesBlockSize)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("RandomCipher: %s", err.Error()))
	}
	block, _ := aes.NewCipher(key)
	return block
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(length int) []byte {
	res := make([]byte, length)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
}

// encryptedRandomLine returns an encrypted random line from a file containing base64-encoded strings.
func encryptedRandomLine(filename string, enc cipher.BlockMode) ([]byte, error) {
	buf, err := randomLine(filename)
	if err != nil {
		return nil, err
	}
	buf = PKCS7Pad(buf, enc.BlockSize())
	enc.CryptBlocks(buf, buf)
	return buf, nil
}

// decryptedValidPadding returns true if a decrypted buffer has valid PKCS#7 padding.
func decryptedValidPadding(buf []byte, dec cipher.BlockMode) bool {
	// NOTE: Modifying the buffer in place might be a bad idea!
	dec.CryptBlocks(buf, buf)
	return ValidPadding(buf, dec.BlockSize())
}

// cbcPaddingOracle returns a CBC padding oracle function, initialization vector, and ciphertext.
func cbcPaddingOracle(filename string) (func([]byte, []byte) error, []byte, []byte, error) {
	block := RandomCipher()
	oracle := func(iv, buf []byte) error {
		if !decryptedValidPadding(buf, cipher.NewCBCDecrypter(block, iv)) {
			return errors.New("psst...invalid padding")
		}
		return nil
	}
	iv := RandomBytes(aesBlockSize)
	ciphertext, err := encryptedRandomLine(filename, cipher.NewCBCEncrypter(block, iv))
	if err != nil {
		return nil, nil, nil, err
	}
	return oracle, iv, ciphertext, nil
}

// cbcBreaker stores information for attacking a CBC padding oracle.
type cbcBreaker struct {
	oracle     func([]byte, []byte) error
	iv         []byte
	ciphertext []byte
}

// newCBCBreaker generates a CBC padding oracle from a file containing base64-encoded strings.
func newCBCBreaker(filename string) (*cbcBreaker, error) {
	oracle, iv, ciphertext, err := cbcPaddingOracle(filename)
	if err != nil {
		return nil, err
	}
	return &cbcBreaker{oracle, iv, ciphertext}, nil
}

/*
func (*cbcBreaker) breakPaddingByte() byte {
}

func (*cbcBreaker) breakBlock(iv, buf []byte) {
}

func (*cbcBreaker) breakOracle() []byte {
}
*/

func main() {
	/*
		x, err := newCBCBreaker("17.txt")
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
	*/
}
