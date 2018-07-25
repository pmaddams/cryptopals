package main

import (
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

// MTRandomRange returns a pseudo-random unsigned 32-bit integer in [lo, hi].
func MTRandomRange(lo, hi uint32) uint32 {
	if lo > hi {
		panic("MTRandomRange: invalid range")
	}
	mt := NewMT(uint32(time.Now().Unix()))
	return lo + mt.Uint32n(hi-lo+1)
}

// breakMT takes an MT19937 output and the current time, and returns the seed.
func breakMT(n, unixTime uint32) (uint32, error) {
	for seed := unixTime; seed > 0; seed-- {
		if NewMT(seed).Uint32() == n {
			return seed, nil
		}
	}
	return 0, errors.New("breakMT: nothing found")
}

func main() {
	seed := uint32(time.Now().Unix())
	mt := NewMT(seed)

	n, err := breakMT(mt.Uint32(), seed+MTRandomRange(40, 1000))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if n == seed {
		fmt.Println("success")
	}
}
