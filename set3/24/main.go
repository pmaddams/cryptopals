// 24. Create the MT19937 stream cipher and break it

package main

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	arraySize   = 624
	offset      = 397
	multiplier  = 1812433253
	upperMask   = 0x80000000
	lowerMask   = 0x7fffffff
	coefficient = 0x9908b0df
	temperMask1 = 0x9d2c5680
	temperMask2 = 0xefc60000
)

func main() {
	seed := uint16(time.Now().Unix() & 0xffff)
	stream := NewMTCipher(uint32(seed))

	plaintext := bytes.Repeat([]byte{'a'}, 14)
	ciphertext := encrypt(stream, plaintext)

	n, err := breakMTCipher(ciphertext, plaintext)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if n == seed {
		fmt.Println("success: recovered 16-bit seed")
	}
	if isRecent(passwordToken()) {
		fmt.Println("token generated from recent timestamp")
	}
}

// encrypt returns an encrypted buffer prefixed with 5-10 random bytes.
func encrypt(stream cipher.Stream, buf []byte) []byte {
	res := append(MTBytes(int(MTInRange(5, 10))), buf...)
	stream.XORKeyStream(res, res)
	return res
}

// breakMTCipher returns the 16-bit seed for an MT19937 stream cipher.
func breakMTCipher(ciphertext, plaintext []byte) (uint16, error) {
	if len(ciphertext) < len(plaintext) {
		return 0, errors.New("breakMTCipher: invalid ciphertext")
	}
	// Encrypt the length of the ciphertext, but ignore the prefix.
	tmp := make([]byte, len(ciphertext))
	n := len(ciphertext) - len(plaintext)

	for i := 0; i < 65536; i++ {
		stream := NewMTCipher(uint32(i))
		stream.XORKeyStream(tmp[:n], tmp[:n])
		stream.XORKeyStream(tmp[n:], plaintext)
		if bytes.Equal(tmp[n:], ciphertext[n:]) {
			return uint16(i), nil
		}
	}
	return 0, errors.New("breakMTCipher: nothing found")
}

// isRecent returns true if the password token was generated from a recent timestamp.
func isRecent(buf []byte) bool {
	n := uint32(time.Now().Unix())
	tmp := make([]byte, len(buf))

	// Check back at most 24 hours.
	for i := 0; i < 24*60*60; i++ {
		stream := NewMTCipher(n - uint32(i))
		stream.XORKeyStream(tmp, tmp)
		if bytes.Equal(buf, tmp) {
			return true
		}
		clear(tmp)
	}
	return false
}

// passwordToken returns a 128-bit password reset token using the current time.
func passwordToken() []byte {
	return MTBytes(16)
}

// MT represents an MT19937 PRNG.
type MT struct {
	state [arraySize]uint32
	pos   int
}

// NewMT initializes and returns a new PRNG.
func NewMT(seed uint32) *MT {
	var mt MT
	mt.state[0] = seed
	for i := 1; i < len(mt.state); i++ {
		mt.state[i] = multiplier*
			(mt.state[i-1]^(mt.state[i-1]>>30)) +
			uint32(i)
	}
	mt.twist()
	return &mt
}

// Uint32 returns a pseudo-random unsigned 32-bit integer.
func (mt *MT) Uint32() uint32 {
	n := temper(mt.state[mt.pos])
	mt.pos++
	if mt.pos == len(mt.state) {
		mt.twist()
		mt.pos = 0
	}
	return n
}

// Uint32n returns a pseudo-random unsigned 32-bit integer in [0, n).
func (mt *MT) Uint32n(n uint32) uint32 {
	if n == 0 {
		panic("Uint32n: invalid range")
	}
	return uint32(float64(mt.Uint32()) *
		float64(n-1) / float64(^uint32(0)))
}

// twist scrambles the state array.
func (mt *MT) twist() {
	for i := range mt.state {
		n := (mt.state[i] & upperMask) | (mt.state[(i+1)%len(mt.state)] & lowerMask)
		mt.state[i] = mt.state[(i+offset)%len(mt.state)] ^ (n >> 1)
		if n&1 == 1 {
			mt.state[i] ^= coefficient
		}
	}
}

// temper applies the tempering transformation.
func temper(n uint32) uint32 {
	n ^= n >> 11
	n ^= (n << 7) & temperMask1
	n ^= (n << 15) & temperMask2
	n ^= n >> 18

	return n
}

// mtCipher represents an MT19937 stream cipher.
type mtCipher struct {
	*MT
}

// NewMTCipher creates a new MT19937 cipher.
func NewMTCipher(seed uint32) cipher.Stream {
	return mtCipher{NewMT(seed)}
}

// XORKeyStream encrypts a buffer with MT19937.
func (x mtCipher) XORKeyStream(dst, src []byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ byte(x.Uint32()&0xff)
	}
}

// MTBytes returns a pseudo-random buffer of the desired length.
func MTBytes(n int) []byte {
	buf := make([]byte, n)
	stream := NewMTCipher(uint32(time.Now().Unix()))
	stream.XORKeyStream(buf, buf)
	return buf
}

// MTInRange returns a pseudo-random unsigned 32-bit integer in [lo, hi].
func MTInRange(lo, hi uint32) uint32 {
	if lo > hi {
		panic("MTInRange: invalid range")
	}
	mt := NewMT(uint32(time.Now().Unix()))
	return lo + mt.Uint32n(hi-lo+1)
}

// clear overwrites a buffer with zeroes.
func clear(buf []byte) {
	// The compiler should optimize this loop.
	for i := range buf {
		buf[i] = 0
	}
}
