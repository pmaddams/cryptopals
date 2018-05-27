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

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

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
func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return ecbEncrypter{ecb{block}}
}

// ecbEncrypter.CryptBlocks encrypts a buffer in ECB mode.
func (mode ecbEncrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.b.Encrypt)
}

// ecbDecrypter embeds ecb.
type ecbDecrypter struct{ ecb }

// NewECBDecrypter returns a block mode for ECB decryption.
func NewECBDecrypter(block cipher.Block) cipher.BlockMode {
	return ecbDecrypter{ecb{block}}
}

// ecbDecrypter.CryptBlocks decrypts a buffer in ECB mode.
func (mode ecbDecrypter) CryptBlocks(dst, src []byte) {
	mode.cryptBlocks(dst, src, mode.b.Decrypt)
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(length int) []byte {
	res := make([]byte, length)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
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
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	return buf[:len(buf)-int(b)], nil
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
	block, err := aes.NewCipher(RandomBytes(aesBlockSize))
	if err != nil {
		panic(err.Error())
	}
	enc, dec := NewECBEncrypter(block), NewECBDecrypter(block)

	toCut := encryptedProfileFor("XXXXXXXXXXadmin", enc)
	toPaste := encryptedProfileFor("anonymous.coward@guerrillamail.com", enc)

	cut := toCut[len(toCut)-aesBlockSize:]
	paste := toPaste[:len(toPaste)-aesBlockSize]
	if decryptedRoleAdmin(append(paste, cut...), dec) {
		fmt.Println("success")
	}
}
