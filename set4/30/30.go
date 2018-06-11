package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
)

const (
	// An MD4 checksum is 16 bytes long.
	md4Size = 16

	// MD4 has a block size of 64 bytes.
	md4BlockSize = 64

	s0 = 0x67452301
	s1 = 0xefcdab89
	s2 = 0x98badcfe
	s3 = 0x10325476

	c1 = 0x5a827999
	c2 = 0x6ed9eba1
)

type md4 struct {
	state [4]uint32
	buf   [md4BlockSize]byte
	pos   int
	n     int
}

func NewMD4() hash.Hash {
	h := new(md4)
	h.Reset()
	return h
}

func (h *md4) Size() int {
	return md4Size
}

func (h *md4) BlockSize() int {
	return md4BlockSize
}

func (h *md4) Reset() {
	h.state[0] = s0
	h.state[1] = s1
	h.state[2] = s2
	h.state[3] = s3
	h.pos = 0
	h.n = 0
}

func f1(b, c, d uint32) uint32 {
	return d ^ (b & (c ^ d))
}

func f2(b, c, d uint32) uint32 {
	return (b & c) | (b & d) | (c & d)
}

func f3(b, c, d uint32) uint32 {
	return b ^ c ^ d
}

func step(f func(uint32, uint32, uint32) uint32, a, b, c, d, in, shift uint32) uint32 {
	res := a + f(b, c, d) + in
	res = (res << shift) | (res >> (32 - shift))

	return res
}

func (h *md4) transform() {
	a := h.state[0]
	b := h.state[1]
	c := h.state[2]
	d := h.state[3]

	var in [16]uint32
	for i := range in {
		in[i] = binary.LittleEndian.Uint32(h.buf[i*4 : (i+1)*4])
	}

	a = step(f1, a, b, c, d, in[0], 3)
	d = step(f1, d, a, b, c, in[1], 7)
	c = step(f1, c, d, a, b, in[2], 11)
	b = step(f1, b, c, d, a, in[3], 19)
	a = step(f1, a, b, c, d, in[4], 3)
	d = step(f1, d, a, b, c, in[5], 7)
	c = step(f1, c, d, a, b, in[6], 11)
	b = step(f1, b, c, d, a, in[7], 19)
	a = step(f1, a, b, c, d, in[8], 3)
	d = step(f1, d, a, b, c, in[9], 7)
	c = step(f1, c, d, a, b, in[10], 11)
	b = step(f1, b, c, d, a, in[11], 19)
	a = step(f1, a, b, c, d, in[12], 3)
	d = step(f1, d, a, b, c, in[13], 7)
	c = step(f1, c, d, a, b, in[14], 11)
	b = step(f1, b, c, d, a, in[15], 19)

	a = step(f2, a, b, c, d, c1+in[0], 3)
	d = step(f2, d, a, b, c, c1+in[4], 5)
	c = step(f2, c, d, a, b, c1+in[8], 9)
	b = step(f2, b, c, d, a, c1+in[12], 13)
	a = step(f2, a, b, c, d, c1+in[1], 3)
	d = step(f2, d, a, b, c, c1+in[5], 5)
	c = step(f2, c, d, a, b, c1+in[9], 9)
	b = step(f2, b, c, d, a, c1+in[13], 13)
	a = step(f2, a, b, c, d, c1+in[2], 3)
	d = step(f2, d, a, b, c, c1+in[6], 5)
	c = step(f2, c, d, a, b, c1+in[10], 9)
	b = step(f2, b, c, d, a, c1+in[14], 13)
	a = step(f2, a, b, c, d, c1+in[3], 3)
	d = step(f2, d, a, b, c, c1+in[7], 5)
	c = step(f2, c, d, a, b, c1+in[11], 9)
	b = step(f2, b, c, d, a, c1+in[15], 13)

	a = step(f3, a, b, c, d, c2+in[0], 3)
	d = step(f3, d, a, b, c, c2+in[8], 9)
	c = step(f3, c, d, a, b, c2+in[4], 11)
	b = step(f3, b, c, d, a, c2+in[12], 15)
	a = step(f3, a, b, c, d, c2+in[2], 3)
	d = step(f3, d, a, b, c, c2+in[10], 9)
	c = step(f3, c, d, a, b, c2+in[6], 11)
	b = step(f3, b, c, d, a, c2+in[14], 15)
	a = step(f3, a, b, c, d, c2+in[1], 3)
	d = step(f3, d, a, b, c, c2+in[9], 9)
	c = step(f3, c, d, a, b, c2+in[5], 11)
	b = step(f3, b, c, d, a, c2+in[13], 15)
	a = step(f3, a, b, c, d, c2+in[3], 3)
	d = step(f3, d, a, b, c, c2+in[11], 9)
	c = step(f3, c, d, a, b, c2+in[7], 11)
	b = step(f3, b, c, d, a, c2+in[15], 15)

	h.state[0] += a
	h.state[1] += b
	h.state[2] += c
	h.state[3] += d
}

func (h *md4) Write(buf []byte) (int, error) {
	n := len(buf)
	h.n += n
	if h.pos > 0 {
		toHash := copy(h.buf[h.pos:], buf)
		h.pos += toHash
		if h.pos == h.BlockSize() {
			h.transform()
			h.pos = 0
		}
		buf = buf[:toHash]
	}
	for len(buf) >= h.BlockSize() {
		copy(h.buf[:], buf)
		h.transform()
		buf = buf[:h.BlockSize()]
	}
	if len(buf) > 0 {
		h.pos += copy(h.buf[:], buf)
	}
	return n, nil
}

// BitPadding returns bit padding for the given buffer length.
func BitPadding(n, blockSize int, endian binary.ByteOrder) []byte {
	if n < 0 || blockSize < 8 {
		panic("BitPadding: invalid parameters")
	}
	var zeros int
	// Account for the padding "1" byte.
	if rem := (n + 1) % blockSize; rem > blockSize-8 {
		zeros = 2*blockSize - rem
	} else {
		zeros = blockSize - rem
	}
	res := append([]byte{1}, bytes.Repeat([]byte{0}, zeros)...)

	// Write the bit count as an unsigned 64-bit integer.
	endian.PutUint64(res[len(res)-8:], uint64(n) << 3)

	return res
}

func (h *md4) Sum(buf []byte) []byte {
	h.Write(BitPadding(h.n, h.BlockSize(), binary.LittleEndian))

	res := make([]byte, h.Size())
	binary.LittleEndian.PutUint32(res[0:4], h.state[0])
	binary.LittleEndian.PutUint32(res[4:8], h.state[1])
	binary.LittleEndian.PutUint32(res[8:12], h.state[2])
	binary.LittleEndian.PutUint32(res[12:16], h.state[3])

	return append(buf, res...)
}

func main() {
	h := NewMD4()
	io.WriteString(h, "hello world")
	fmt.Printf("%x\n", h.Sum([]byte{}))
}
