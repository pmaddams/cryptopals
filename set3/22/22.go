package main

import (
	"errors"
	"fmt"
	weak "math/rand"
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

// MT19937 contains state for the MT19937 PRNG.
type MT19937 struct {
	state [arraySize]uint32
	pos   int
}

// NewMT19937 initializes and returns a new PRNG.
func NewMT19937(seed uint32) *MT19937 {
	var mt MT19937
	mt.state[0] = seed
	for i := 1; i < arraySize; i++ {
		mt.state[i] = multiplier*
			(mt.state[i-1]^(mt.state[i-1]>>30)) +
			uint32(i)
	}
	mt.twist()
	return &mt
}

// twist scrambles the PRNG state array.
func (mt *MT19937) twist() {
	for i := 0; i < arraySize; i++ {
		n := (mt.state[i] & upperMask) | (mt.state[(i+1)%arraySize] & lowerMask)
		mt.state[i] = mt.state[(i+offset)%arraySize] ^ (n >> 1)
		if n%2 != 0 {
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
func (mt *MT19937) Uint32() uint32 {
	n := temper(mt.state[mt.pos])
	mt.pos++
	if mt.pos == arraySize {
		mt.twist()
		mt.pos = 0
	}
	return n
}

// RandomRange returns a pseudo-random non-negative integer in [lo, hi].
// The output should not be used in a security-sensitive context.
func RandomRange(lo, hi int) int {
	if lo < 0 || lo > hi {
		panic("RandomRange: invalid range")
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	return lo + weak.Intn(hi-lo+1)
}

// breakSeed takes a PRNG output and the current time, and returns the seed.
func breakSeed(n, unixTime uint32) (uint32, error) {
	for seed := unixTime; seed > 0; seed-- {
		if NewMT19937(seed).Uint32() == n {
			return seed, nil
		}
	}
	return uint32(0), errors.New("breakSeed")
}

func main() {
	seed := uint32(time.Now().Unix())
	mt := NewMT19937(seed)

	n, err := breakSeed(mt.Uint32(), seed+uint32(RandomRange(40, 1000)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	if n == seed {
		fmt.Println("success")
	}
}
