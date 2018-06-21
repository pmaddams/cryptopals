package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
)

// ProfileFor returns a query string identifying an email address as a user.
func ProfileFor(email string) string {
	return url.Values{
		"email": {email},
		"role":  {"user"},
	}.Encode()
}

// RoleAdmin returns true if a query string is valid and contains "role=admin".
func RoleAdmin(query string) bool {
	v, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	return v.Get("role") == "admin"
}

// ecb represents a generic ECB block mode.
type ecb struct{ c cipher.Block }

// BlockSize returns the cipher block size.
func (x ecb) BlockSize() int {
	return x.c.BlockSize()
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

// ecbEncrypter represents an ECB encryption block mode.
type ecbEncrypter struct{ ecb }

// NewECBEncrypter returns a block mode for ECB encryption.
func NewECBEncrypter(c cipher.Block) cipher.BlockMode {
	return ecbEncrypter{ecb{c}}
}

// ecbEncrypter.CryptBlocks encrypts a buffer in ECB mode.
func (mode ecbEncrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.c.Encrypt)
}

// ecbDecrypter represents an ECB decryption block mode.
type ecbDecrypter struct{ ecb }

// NewECBDecrypter returns a block mode for ECB decryption.
func NewECBDecrypter(c cipher.Block) cipher.BlockMode {
	return ecbDecrypter{ecb{c}}
}

// ecbDecrypter.CryptBlocks decrypts a buffer in ECB mode.
func (mode ecbDecrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.c.Decrypt)
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
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
	if len(buf) < blockSize {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	return dup(buf)[:len(buf)-int(b)], nil
}

// encryptedProfileFor returns an encrypted user profile for an email address.
func encryptedProfileFor(email string, enc cipher.BlockMode) []byte {
	buf := PKCS7Pad([]byte(ProfileFor(email)), enc.BlockSize())
	enc.CryptBlocks(buf, buf)
	return buf
}

// decryptedRoleAdmin returns true if a decrypted query string contains "role=admin".
func decryptedRoleAdmin(buf []byte, dec cipher.BlockMode) bool {
	tmp := make([]byte, len(buf))
	dec.CryptBlocks(tmp, buf)
	tmp, err := PKCS7Unpad(tmp, dec.BlockSize())
	if err != nil {
		return false
	}
	return RoleAdmin(string(tmp))
}

func main() {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	enc, dec := NewECBEncrypter(c), NewECBDecrypter(c)

	toCut := encryptedProfileFor("XXXXXXXXXXadmin", enc)
	toPaste := encryptedProfileFor("anonymous.coward@guerrillamail.com", enc)

	cut := toCut[len(toCut)-aes.BlockSize:]
	paste := toPaste[:len(toPaste)-aes.BlockSize]
	if decryptedRoleAdmin(append(paste, cut...), dec) {
		fmt.Println("success")
	}
}
