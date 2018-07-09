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

// MT represents an MT19937 (32-bit Mersenne Twister) PRNG.
type MT struct {
	state [arraySize]uint32
	pos   int
}

// NewMT initializes and returns a new MT19937 PRNG.
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

// twist scrambles the MT19937 state array.
func (mt *MT) twist() {
	for i := range mt.state {
		n := (mt.state[i] & upperMask) | (mt.state[(i+1)%len(mt.state)] & lowerMask)
		mt.state[i] = mt.state[(i+offset)%len(mt.state)] ^ (n >> 1)
		if n&1 == 1 {
			mt.state[i] ^= coefficient
		}
	}
}

// temper applies the MT19937 tempering transformation.
func temper(n uint32) uint32 {
	n ^= n >> 11
	n ^= (n << 7) & temperMask1
	n ^= (n << 15) & temperMask2
	n ^= n >> 18

	return n
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
		panic("Intn: invalid bound")
	}
	return uint32(float64(mt.Uint32()) *
		float64(n-1) / float64(^uint32(0)))
}

// mtCipher represents an MT19937 stream cipher.
type mtCipher struct {
	*MT
}

// NewMTCipher creates a new MT19937 stream cipher.
func NewMTCipher(seed uint32) cipher.Stream {
	return mtCipher{NewMT(seed)}
}

// XORKeyStream encrypts a buffer with MT19937.
func (stream mtCipher) XORKeyStream(dst, src []byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ byte(stream.Uint32()&0xff)
	}
}

// MTRandomRange returns a pseudo-random unsigned 32-bit integer in [lo, hi].
func MTRandomRange(lo, hi uint32) uint32 {
	if lo > hi {
		panic("MTRandomRange: invalid range")
	}
	mt := NewMT(uint32(time.Now().Unix()))
	return lo + mt.Uint32n(hi-lo+1)
}

// MTRandomBytes returns a pseudo-random buffer of the desired length.
func MTRandomBytes(n int) []byte {
	buf := make([]byte, n)
	stream := NewMTCipher(uint32(time.Now().Unix()))
	stream.XORKeyStream(buf, buf)
	return buf
}

// encryptWithPrefix returns an encrypted buffer prefixed with 5-10 random bytes.
func encryptWithPrefix(stream cipher.Stream, buf []byte) []byte {
	res := append(MTRandomBytes(int(MTRandomRange(5, 10))), buf...)
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

// randomToken returns a 128-bit password reset token using the current time.
func randomToken() []byte {
	return MTRandomBytes(16)
}

// clear overwrites a buffer with zeroes.
func clear(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// checkToken returns true if the token was generated from a recent timestamp.
func checkToken(buf []byte) bool {
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

func main() {
	seed := uint16(time.Now().Unix() & 0xffff)
	stream := NewMTCipher(uint32(seed))

	plaintext := bytes.Repeat([]byte{'a'}, 14)
	ciphertext := encryptWithPrefix(stream, plaintext)

	n, err := breakMTCipher(ciphertext, plaintext)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if n == seed {
		fmt.Println("success: recovered 16-bit seed")
	}
	if checkToken(randomToken()) {
		fmt.Println("token generated from timestamp")
	}
}
