package main

import (
	"crypto/cipher"
)

type ctr struct {
	b   cipher.Block
	ctr []byte
}

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}

func NewCTR(block cipher.Block, iv []byte) cipher.Stream {
	if block.BlockSize() != len(iv) {
		panic("NewCTR: initialization vector length must equal block size")
	}
	return ctr{block, dup(iv)}
}

func (stream ctr) inc() {
	for i := len(stream.ctr) - 1; i >= 0; i-- {
		stream.ctr[i]++
		if stream.ctr[i] != 0 {
			break
		}
	}
}

func (stream ctr) XORKeyStream(dst, src []byte) {
}

func main() {
}
