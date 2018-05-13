package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// randomCipher returns an AES cipher with a random key.
func randomCipher() cipher.Block {
	key := make([]byte, aesBlockSize)
	if _, err := rand.Read(key); err != nil {
		panic(err.Error())
	}
	block, _ := aes.NewCipher(key)
	return block
}

// evilBuffer returns a buffer that makes it easy to detect ECB.
func evilBuffer() []byte {
	return bytes.Repeat([]byte{'a'}, 3*aesBlockSize)
}

func main() {
}
