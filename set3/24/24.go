package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"
)

const arraySize = 624
const offset = 397
const multiplier = 1812433253
const upperMask = 0x80000000
const lowerMask = 0x7fffffff
const coefficient = 0x9908b0df
const temperMask1 = 0x9d2c5680
const temperMask2 = 0xefc60000

// MT contains state for the MT19937 (32-bit Mersenne Twister) PRNG.
type MT struct {
	state [arraySize]uint32
	pos   int
}

// NewMT initializes and returns a new MT19937 PRNG.
func NewMT(seed uint32) *MT {
	var mt MT
	mt.state[0] = seed
	for i := 1; i < arraySize; i++ {
		mt.state[i] = multiplier*
			(mt.state[i-1]^(mt.state[i-1]>>30)) +
			uint32(i)
	}
	mt.twist()
	return &mt
}

// twist scrambles the MT19937 state array.
func (mt *MT) twist() {
	for i := 0; i < arraySize; i++ {
		n := (mt.state[i] & upperMask) | (mt.state[(i+1)%arraySize] & lowerMask)
		mt.state[i] = mt.state[(i+offset)%arraySize] ^ (n >> 1)
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
	if mt.pos == arraySize {
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

// Range returns a pseudo-random unsigned 32-bit integer in [lo, hi].
func (mt *MT) Range(lo, hi uint32) uint32 {
	if lo > hi {
		panic("Range: invalid range")
	}
	return lo + mt.Uint32n(hi-lo+1)
}

// XORKeyStream uses the lowest 8 bits of MT19937 output as a stream cipher.
func (mt *MT) XORKeyStream(dst, src []byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ byte(mt.Uint32()&0xff)
	}
}

// Bytes returns a pseudo-random buffer of the desired length.
func (mt *MT) Bytes(length int) []byte {
	res := make([]byte, length)
	mt.XORKeyStream(res, res)
	return res
}

// encryptWithPrefix returns an encrypted buffer prefixed with 5-10 random bytes.
func (mt *MT) encryptWithPrefix(buf []byte) []byte {
	aux := NewMT(uint32(time.Now().Unix()))
	res := append(aux.Bytes(int(aux.Range(5, 10))), buf...)
	mt.XORKeyStream(res, res)
	return res
}

// breakCipherSeed returns the 16-bit seed for an MT19937 stream cipher.
func breakCipherSeed(ciphertext, plaintext []byte) (uint16, error) {
	if len(ciphertext) < len(plaintext) {
		return 0, errors.New("breakCipherSeed: invalid ciphertext")
	}
	// Encrypt the length of the ciphertext, but ignore the prefix.
	tmp := make([]byte, len(ciphertext))
	n := len(ciphertext) - len(plaintext)

	for i := 0; i < 65536; i++ {
		mt := NewMT(uint32(i))
		mt.XORKeyStream(tmp[:n], tmp[:n])
		mt.XORKeyStream(tmp[n:], plaintext)
		if bytes.Equal(tmp[n:], ciphertext[n:]) {
			return uint16(i), nil
		}
	}
	return 0, errors.New("breakCipherSeed: nothing found")
}

// token returns a 128-bit password reset token using the current time.
func (mt *MT) token() []byte {
	return mt.Bytes(16)
}

// checkToken returns true if the token was generated from a recent timestamp.
func checkToken(buf []byte) bool {
	n := uint32(time.Now().Unix())

	// Check back at most 24 hours.
	for i := 0; i < 24*60*60; i++ {
		mt := NewMT(n - uint32(i))
		if bytes.Equal(buf, mt.Bytes(len(buf))) {
			return true
		}
	}
	return false
}

func main() {
	seed := uint16(time.Now().Unix() & 0xffff)
	mt := NewMT(uint32(seed))
	plaintext := []byte("aaaaaaaaaaaaaa")
	ciphertext := mt.encryptWithPrefix(plaintext)

	n, err := breakCipherSeed(ciphertext, plaintext)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	if n == seed {
		fmt.Println("success: recovered 16-bit seed")
	}

	mt = NewMT(uint32(time.Now().Unix()))
	if checkToken(mt.token()) {
		fmt.Println("token generated from timestamp")
	}
}
